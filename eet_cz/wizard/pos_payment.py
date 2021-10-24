from odoo import models


class PosMakePayment(models.TransientModel):
    _inherit = 'pos.make.payment'

    def check(self):
        order = self.env['pos.order'].browse(self.env.context.get('active_id', False))
        if order.amount_total <= 0.00:
            order.register_pos_sales()
        return super(PosMakePayment, self).check()
