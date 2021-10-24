from odoo import models,fields


class Partner(models.Model):
    _inherit = 'res.partner'

    estd_reg_no = fields.Integer('Establishment Reg. No.')
    sale_regime = fields.Selection([
        ('0', 'Regular'),
        ('1', 'Simplified')])
    cert_password = fields.Char('Certificate Password',
        help="Enter password of PKCS#12 certificate attached in attachments.")

