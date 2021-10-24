from odoo import fields, models


class ProductTemplate(models.Model):
    _inherit = 'product.template'

    coupon = fields.Boolean('Coupon')
    direct_representation = fields.Boolean('Direct Representation')
    auth_taxpayer_id = fields.Many2one('res.partner', string='Authorized Taxpayer')

