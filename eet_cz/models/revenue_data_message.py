import hashlib
import pytz
import requests
import uuid
import werkzeug

from base64 import b64encode
from datetime import datetime
from lxml import etree
from OpenSSL import crypto
from requests.exceptions import ConnectionError

try:
    from StringIO import StringIO
except ImportError:
    from io import BytesIO as StringIO

from odoo import models, fields, api, _
from odoo.exceptions import Warning


class RevenueDataMessage(models.Model):
    _name = 'revenue.data.message'
    _description = 'Sales Data Message'

    @api.model
    def _selection_target_model(self):
        ir_models = self.env['ir.model'].search([])
        return [(model.model, model.name) for model in ir_models]

    @api.depends('response')
    def _get_fik(self):
        for cls_obj in self:
            if cls_obj.response:
                confirmation_obj = etree.XML(cls_obj.response.encode()).find(
                    'soap:Body/eet:Odpoved/eet:Potvrzeni', {
                        'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
                        'eet': 'http://fs.mfcr.cz/eet/schema/v3'
                    })
                try:
                    cls_obj.fik = confirmation_obj.attrib['fik']
                except AttributeError:
                    cls_obj.fik = ''
            else:
                cls_obj.fik = ''

    @api.depends('message')
    def _set_pkp_code(self):
        for cls_obj in self:
            if cls_obj.message:
                pkp_elem = etree.XML(cls_obj.message).find('soap:Body/eet:Trzba/eet:KontrolniKody/eet:pkp', {
                    'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
                    'eet': 'http://fs.mfcr.cz/eet/schema/v3',
                })
                cls_obj.pkp_code = pkp_elem.text
            else:
                cls_obj.pkp_code = ''

    @api.depends('message')
    def _set_bkp_code(self):
        for cls_obj in self:
            if cls_obj.message:
                bkp_elem = etree.XML(cls_obj.message).find('soap:Body/eet:Trzba/eet:KontrolniKody/eet:bkp', {
                    'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
                    'eet': 'http://fs.mfcr.cz/eet/schema/v3',
                })
                cls_obj.bkp_code = bkp_elem.text
            else:
                cls_obj.bkp_code = ''

    @api.depends('fik')
    def _get_status(self):
        for cls_obj in self:
            if cls_obj.fik:
                cls_obj.state = 'success'
            else:
                cls_obj.state = 'fail'

    def _extract_data(self):
        for msg_id in self:
            msg_id.vat = ''
            msg_id.auth_vat = ''
            msg_id.estd_reg_no = ''
            msg_id.sale_regime = ''
            if msg_id.message:
                ns = {
                    'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
                    'eet': 'http://fs.mfcr.cz/eet/schema/v3',
                }
                data_elem = etree.XML(msg_id.message).find('soap:Body/eet:Trzba/eet:Data', ns)
                msg_id.vat = data_elem.attrib['dic_popl']
                if data_elem.attrib.get('dic_poverujiciho', False):
                    msg_id.auth_vat = data_elem.attrib['dic_poverujiciho']
                msg_id.estd_reg_no = data_elem.attrib['id_provoz']
                msg_id.sale_regime = data_elem.attrib['rezim']

    name = fields.Reference(string='Name', selection='_selection_target_model')
    company_id = fields.Many2one('res.company', string='Company')
    res_id = fields.Integer('Document ID', required=True)
    res_model = fields.Char('Model', required=True)
    message = fields.Text('Sale Data Message')
    response = fields.Text('Received Response')
    exception = fields.Text('Exception')
    fik = fields.Char(compute='_get_fik', string='FIK', store=True)
    pkp_code = fields.Char(compute='_set_pkp_code', string='PKP Code', store=True)
    bkp_code = fields.Char(compute='_set_bkp_code', string='BKP Code', store=True)
    state = fields.Selection([
        ('fail', 'Fail'),
        ('success', 'Success')], compute='_get_status', string='Status', store=True)
    test_message = fields.Boolean('Test Message')
    vat = fields.Char('Tax ID', compute='_extract_data')
    auth_vat = fields.Char('Auth. Tax ID', compute='_extract_data')
    estd_reg_no = fields.Char('Establishment No.', compute='_extract_data')
    sale_regime = fields.Char('Sale Regime', compute='_extract_data')
    cert_link = fields.Char('Used Certificate Link')
    cert_pwd = fields.Char('Certificate Password')

    def get_normalized_subtree(self, node, includive_prefixes=[]):
        tree = etree.ElementTree(node)
        ss = StringIO()
        tree.write_c14n(
            ss, exclusive=True, inclusive_ns_prefixes=includive_prefixes)
        return ss.getvalue()

    def sign_sale_data_message(self, message, cert_link, cert_pwd):
        ns = {
            'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            'ds': 'http://www.w3.org/2000/09/xmldsig#',
            'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
        }
        e_sale_obj = message.find('soap:Body', ns)
        e_sale = self.get_normalized_subtree(e_sale_obj, ['soap'])
        digest = b64encode(hashlib.sha256(e_sale).digest())
        digest_val_tag = message.find(
            'soap:Header/wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue', ns)
        digest_val_tag.text = digest
        certificate = crypto.load_pkcs12(open(cert_link, 'rb').read(), cert_pwd)
        pkey = certificate.get_privatekey()
        sign_info_obj = message.find(
            'soap:Header/wsse:Security/ds:Signature/ds:SignedInfo', ns)
        sign_info = self.get_normalized_subtree(sign_info_obj, ['soap'])
        sign_value_tag = message.find('soap:Header/wsse:Security/ds:Signature/ds:SignatureValue', ns)
        sign_value_tag.text = b64encode(crypto.sign(pkey, sign_info, 'sha256'))

    def resend(self):
        url = 'https://prod.eet.cz/eet/services/EETServiceSOAP/v3'
        message = etree.XML(self.message)
        header_elem = message.find('soap:Body/eet:Trzba/eet:Hlavicka', {
            'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
            'eet': 'http://fs.mfcr.cz/eet/schema/v3'
        })
        uuid_str = str(uuid.UUID(bytes=datetime.now().strftime('%Y-%m-%d%H%M%S').encode(), version=4))
        current_time_obj = datetime.now(pytz.timezone(self.env.user.tz or 'UTC'))
        header_elem.set('uuid_zpravy', uuid_str)
        header_elem.set('dat_odesl', current_time_obj.replace(microsecond=0).isoformat())
        header_elem.set('prvni_zaslani', '0')
        self.sign_sale_data_message(message, self.cert_link, self.cert_pwd)
        message = etree.tostring(message)
        try:
            r = requests.post(url, message)
            response = werkzeug.utils.unescape(r.content.decode())
        except ConnectionError as e:
            raise Warning(_('Unable to connect.'))
        self.write({
            'message': message,
            'response': response,
            })
