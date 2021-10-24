from datetime import datetime

import pytz

from odoo import models, fields


class EETConnectionTest(models.TransientModel):
    _name = 'eet.connection.test'

    environment = fields.Selection([('production', 'Production'), ('playground', 'Playground')],
                                   string='Environment')
    payment_id = fields.Many2one('account.payment', string='Payment')
    estd_reg_no = fields.Integer('Establishment Reg. No.', default=1)

    def test_connection(self):
        datetime_obj = pytz.timezone(self.env.user.tz or 'UTC').localize( \
            datetime.combine(self.payment_id.payment_date, datetime.min.time()))
        if self.environment == 'playground':
            url = 'https://pg.eet.cz/eet/services/EETServiceSOAP/v3'
        else:
            url = 'https://prod.eet.cz/eet/services/EETServiceSOAP/v3'
        data_dict = {
            'celk_trzba': format(self.payment_id.amount, '.2f'),
            'dat_trzby': datetime_obj.isoformat(),
            'dic_popl': self.env.user.company_id.vat or '',
            'id_pokl': 'Test Cash Register',
            'id_provoz': str(self.estd_reg_no),
            'porad_cis': self.payment_id.name or '',
            'rezim': self.env.user.company_id.sale_regime or '',
        }
        self.env['eet.message'].render(self.payment_id, data_dict, environ=self.environment, test_message=True, url=url)
