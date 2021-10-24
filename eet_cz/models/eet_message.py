import hashlib
import pytz
import re
import requests
import uuid
import werkzeug

from base64 import b64encode, b64decode, b16encode
from datetime import datetime
from lxml import etree
from OpenSSL import crypto
from requests.exceptions import ConnectionError
try:
    from StringIO import StringIO
except ImportError:
    from io import BytesIO as StringIO

from odoo import models, _
from odoo.exceptions import UserError


class SaleDataMessage(models.AbstractModel):
    _name = 'eet.message'
    _description = 'EET Message'

    cert_link_used = None
    cert_pwd_used = None

    ns = {
        'soap': '{http://schemas.xmlsoap.org/soap/envelope/}',
        'wsse': '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}',
        'ds': '{http://www.w3.org/2000/09/xmldsig#}',
    }

    def get_normalized_subtree(self, node, includive_prefixes=[]):
        tree = etree.ElementTree(node)
        ss = StringIO()
        tree.write_c14n(
            ss, exclusive=True, inclusive_ns_prefixes=includive_prefixes)
        return ss.getvalue()

    def render(self, doc_obj, data_dict, environ='production', test_message=False, url=None, cert_path=None, cert_password=None):
        self.cert_link_used = None
        self.cert_pwd_used = None
        data = self.prepare_sale_data_message(doc_obj, environ, data_dict, test_message=test_message,
            cert_path=cert_path, cert_password=cert_password)
        content = self.env.ref('eet_cz.eet_message_template').render(data)
        content = re.sub('\n\s*', '', content.decode())
        content = etree.tostring(etree.fromstring(content), pretty_print=True)
        content = self.sign_sale_data_message(doc_obj, content, environ, cert_path=cert_path, cert_password=cert_password)
        self.send_request(doc_obj, content, test_message=False, url=url)
        

    def attach_base64_encoded_x509_cert(self, doc_obj, environ, cert_path=None, cert_password=None):
        certificate = self.get_certificate(doc_obj, environ, cert_path, cert_password)
        encoded_cert = b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate.get_certificate()))
        return encoded_cert

    def calculate_bkp(self, pkp_value):
        decoded_string = b64decode(pkp_value)
        digest = hashlib.sha1(decoded_string).digest()
        base16_string = b16encode(digest)
        bkp_code = '-'.join(re.findall(r'.{8}', base16_string.decode()))
        return bkp_code

    def calculate_pkp(self, data, environ, doc_obj, cert_path=None, cert_password=None):
        dic_popl = data['data']['dic_popl']
        id_provoz = data['data']['id_provoz']
        id_pokl = data['data']['id_pokl']
        porad_cis = data['data']['porad_cis']
        dat_trzby = data['data']['dat_trzby']
        celk_trzba = data['data']['celk_trzba']
        plaintext = dic_popl + '|' + id_provoz + '|' + id_pokl + '|' + porad_cis \
            + '|' + dat_trzby + '|' + celk_trzba
        certificate = self.get_certificate(doc_obj, environ, cert_path, cert_password)
        pkey = certificate.get_privatekey()
        pkp_code = b64encode(crypto.sign(pkey, plaintext, 'sha256'))
        return pkp_code

    def get_certificate(self, doc_obj, environ, cert_link, cert_pwd):
        param_obj = doc_obj.env['ir.config_parameter']
        if environ == 'playground':
            cert_link = param_obj.get_param('pkcs#12_playground_cert')
            cert_pwd = param_obj.get_param('pkcs#12_playground_cert_password')
        else:
            if not cert_link and not cert_pwd:
                cert_link = param_obj.get_param('pkcs#12_operational_cert')
                cert_pwd = param_obj.get_param('pkcs#12_operational_cert_password')
        if not cert_link:
            raise UserError(
                'Please configure a link to certificate under Settings/Technical/Parameters/System Parameters.')
        try:
            self.cert_link_used = cert_link
            self.cert_pwd_used = cert_pwd
            certificate = crypto.load_pkcs12(open(cert_link, 'rb').read(), cert_pwd)
        except (crypto.Error, IsADirectoryError) as e:
            error_message = _(
                'Please check link and password configuration of PKCS#12 certificate bundle.\n'
                'Error: %s') % (e)
            raise UserError(error_message)
        return certificate

    def set_soap_envelope_attribs(self):
        common_id = uuid.uuid4().hex
        return {
            'binarysecuritytoken_id': 'X509-' + common_id,
            'ds_reference_uri': '#id-' + common_id,
            'wsse_reference_uri': '#X509-' + common_id,
            'body_id': 'id-' + common_id,
            'signature_id': 'SIG-' + common_id,
            'keyinfo_id': 'KI-' + common_id,
            'securitytokenreference_id': 'STR-' + common_id,
        }

    def sign_sale_data_message(self, doc_obj, content, environ, cert_path=None, cert_password=None):
        content_obj = etree.fromstring(content)
        body_obj = content_obj.find('{0}Body'.format(self.ns['soap']))
        body = self.get_normalized_subtree(body_obj, ['soap'])
        digest = b64encode(hashlib.sha256(body).digest())
        digest_val_tag = content_obj.find( \
            '{0}Header/{1}Security/{2}Signature/{2}SignedInfo/{2}Reference/{2}DigestValue'.format( \
            self.ns['soap'], self.ns['wsse'], self.ns['ds']))
        digest_val_tag.text = digest
        certificate = self.get_certificate(doc_obj, environ, cert_path, cert_password)
        pkey = certificate.get_privatekey()
        sign_info_obj = content_obj.find( \
            '{0}Header/{1}Security/{2}Signature/{2}SignedInfo'.format(self.ns['soap'], self.ns['wsse'], self.ns['ds']))
        sign_info = self.get_normalized_subtree(sign_info_obj, ['soap'])
        signed_message = b64encode(crypto.sign(pkey, sign_info, 'sha256'))
        sign_value_tag = content_obj.find( \
            '{0}Header/{1}Security/{2}Signature/{2}SignatureValue'.format(self.ns['soap'], self.ns['wsse'], self.ns['ds']))
        sign_value_tag.text = signed_message
        return etree.tostring(content_obj)

    def prepare_sale_data_message(self, doc_obj, environ, data_dict, test_message=False, cert_path=None, cert_password=None):
        data = {}
        current_time_obj = datetime.now(pytz.timezone(doc_obj.env.user.tz or 'UTC'))
        data['soap_env_attribs'] = self.set_soap_envelope_attribs()
        data['certificate'] = self.attach_base64_encoded_x509_cert( \
            doc_obj, environ, cert_path=cert_path, cert_password=cert_password)

        data['header'] = {
            'dat_odesl': current_time_obj.replace(microsecond=0).isoformat(),
            'prvni_zaslani': '1',
            'uuid_zpravy': str(uuid.UUID(bytes=datetime.now().strftime('%Y-%m-%d%H%M%S').encode(), version=4)),
            'overeni': '1' if test_message and environ == 'production' else '0',
        }
        data['data'] = {
            'celk_trzba': data_dict['celk_trzba'],
            'zakl_nepodl_dph': data_dict.get('zakl_nepodl_dph', '0.00'),
            'dat_trzby': data_dict['dat_trzby'],
            'dic_popl': data_dict['dic_popl'],
            'id_pokl': data_dict['id_pokl'],
            'id_provoz': data_dict['id_provoz'],
            'porad_cis': data_dict['porad_cis'],
            'zakl_dan1': data_dict.get('zakl_dan1', '0.00'),
            'dan1': data_dict.get('dan1', '0.00'),
            'zakl_dan2': data_dict.get('zakl_dan2', '0.00'),
            'dan2': data_dict.get('dan2', '0.00'),
            'zakl_dan3': data_dict.get('zakl_dan3', '0.00'),
            'dan3': data_dict.get('dan3', '0.00'),
            'cest_sluz': data_dict.get('cest_sluz', '0.00'),
            'pouzit_zboz1': data_dict.get('pouzit_zboz1', '0.00'),
            'pouzit_zboz2': data_dict.get('pouzit_zboz2', '0.00'),
            'pouzit_zboz3': data_dict.get('pouzit_zboz3', '0.00'),
            'urceno_cerp_zuct': data_dict.get('urceno_cerp_zuct', '0.00'),
            'cerp_zuct': data_dict.get('cerp_zuct', '0.00'),
            'rezim': data_dict['rezim'],
        }
        if data_dict.get('dic_poverujiciho', False):
            data['data'].update({'dic_poverujiciho': data_dict['dic_poverujiciho']})
        data['pkp_code'] = self.calculate_pkp(data, environ, doc_obj, cert_path=cert_path, cert_password=cert_password)
        data['bkp_code'] = self.calculate_bkp(data['pkp_code']).lower()
        return data

    def send_request(self, document, content, test_message=False, url=None):
        if not url:
            url = 'https://prod.eet.cz/eet/services/EETServiceSOAP/v3'
        try:
            r = requests.post(url, content)
            response = werkzeug.utils.unescape(r.content.decode())
            self.register_sale_data_message(document, content, test_message=test_message, response=response)
        except ConnectionError as e:
            self.register_sale_data_message( \
                document, content, test_message=test_message, exception=str(e), exception_class=str(e.__class__))

    def register_sale_data_message(self, doc_obj, content, test_message=False, **kwargs):
        try:
            company_id = doc_obj.company_id.id
        except AttributeError:
            company_id = doc_obj.env.user.company_id.id
        vals = {
            'res_id': doc_obj.id,
            'company_id': company_id,
            'res_model': doc_obj.__class__.id.model_name,
            'name': doc_obj.__class__.id.model_name + ',' + str(doc_obj.id),
            'cert_link': self.cert_link_used,
            'cert_pwd': self.cert_pwd_used,
            'message': content,
            'test_message': test_message
        }
        if kwargs.get('response'):
            vals['response'] = kwargs['response']
        else:
            if kwargs.get('exception_class'):
                # If exception_class exists, then presence of exception key is obvious
                vals['exception'] = kwargs['exception']
        doc_obj.env['revenue.data.message'].create(vals)
