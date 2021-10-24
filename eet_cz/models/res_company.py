from odoo import models, fields


class Company(models.Model):
    _inherit = 'res.company'

    sale_regime = fields.Selection(related='partner_id.sale_regime', string='Sale Regime',
                                   readonly=False)
