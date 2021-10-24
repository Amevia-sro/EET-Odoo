from odoo import models, fields, api

import pytz


class PosOrderLine(models.Model):
    _inherit = 'pos.order.line'

    direct_representation = fields.Boolean('Direct Representation')
    auth_taxpayer = fields.Many2one('res.partner', string='Authorized Taxpayer')

class PosOrder(models.Model):
    _inherit = 'pos.order'

    def set_tax_base_and_vat(self, sale_lines, data_dict, coupon_dict = {}):
        total_sales = 0.0
        tax_base_1 = 0.0
        tax_amount_1 = 0.0
        tax_base_2 = 0.0
        tax_amount_2 = 0.0
        tax_base_3 = 0.0
        tax_amount_3 = 0.0
        for sale in sale_lines:
            total_sales += sale.price_subtotal_incl
            for tax in sale.tax_ids:
                if tax == self.env.ref('l10n_cz.' + str(self.env.company.id) + '_tax_exempted'):
                    data_dict['zakl_nepodl_dph'] = format(sale.price_subtotal, '.2f')
                if tax.rate_type == 'basic':
                    tax_base_1 += sale.price_subtotal
                    tax_amount_1 += tax._compute_amount(sale.price_subtotal,
                        sale.price_unit, quantity=sale.qty)
                if tax.rate_type == 'first_reduced':
                    tax_base_2 += sale.price_subtotal
                    tax_amount_2 += tax._compute_amount(sale.price_subtotal,
                        sale.price_unit, quantity=sale.qty)
                if tax.rate_type == 'second_reduced':
                    tax_base_3 += sale.price_subtotal
                    tax_amount_3 += tax._compute_amount(sale.price_subtotal,
                        sale.price_unit, quantity=sale.qty)
        if coupon_dict.get('redeem_predetermined_tax_coupon_amt', 0.00):
            data_dict['cerp_zuct'] = format(coupon_dict['redeem_predetermined_tax_coupon_amt'], '.2f')
            tax_base_1 -= coupon_dict.get('redeem_zakl_dan1', 0.00)
            tax_amount_1 -= coupon_dict.get('redeem_dan1', 0.00)
            tax_base_2 -= coupon_dict.get('redeem_zakl_dan2', 0.00)
            tax_amount_2 -= coupon_dict.get('redeem_dan2', 0.00)
            tax_base_3 -= coupon_dict.get('redeem_zakl_dan3', 0.00)
            tax_amount_3 -= coupon_dict.get('redeem_dan3', 0.00)
        elif coupon_dict.get('redeem_coupon_amt', 0.00):
            data_dict['cerp_zuct'] = format(coupon_dict['redeem_coupon_amt'], '.2f')
        data_dict['zakl_dan1'] = format(tax_base_1, '.2f')
        data_dict['dan1'] = format(tax_amount_1, '.2f')
        data_dict['zakl_dan2'] = format(tax_base_2, '.2f')
        data_dict['dan2'] = format(tax_amount_2, '.2f')
        data_dict['zakl_dan3'] = format(tax_base_3, '.2f')
        data_dict['dan3'] = format(tax_amount_3, '.2f')
        data_dict['celk_trzba'] = format(total_sales, '.2f')
        return data_dict

    @api.model
    def create_from_ui(self, orders, draft=False):
        orders = super(PosOrder, self).create_from_ui(orders, draft=draft)
        message_data = {}
        for order_dict in orders:
            message_key = self.browse(order_dict['id']).pos_reference
            message_data[message_key] = {
                'vat': [],
                'auth_vat': [],
                'estd_reg_no': [],
                'sale_regime': [],
                'fik': [],
                'bkp': [],
                'pkp': [],
            }
            message_ids = self.env['revenue.data.message'].search([('res_id', '=', order_dict['id']),
                ('res_model', '=', 'pos.order')])
            for message_id in message_ids:
                message_data[message_key]['vat'].append(message_id.vat)
                message_data[message_key]['auth_vat'].append(message_id.auth_vat)
                message_data[message_key]['estd_reg_no'].append(message_id.estd_reg_no)
                message_data[message_key]['sale_regime'].append(message_id.sale_regime)
                message_data[message_key]['bkp'].append(message_id.bkp_code)
                if message_id.fik:
                    message_data[message_key]['fik'].append(message_id.fik)
                else:
                    message_data[message_key]['pkp'].append(message_id.pkp_code)
            message_data[message_key]['vat'] = list(dict.fromkeys(message_data[message_key]['vat']))
            message_data[message_key]['auth_vat'] = list(dict.fromkeys(message_data[message_key]['auth_vat']))
            message_data[message_key]['estd_reg_no'] = list(dict.fromkeys(message_data[message_key]['estd_reg_no']))
            message_data[message_key]['sale_regime'] = list(dict.fromkeys(message_data[message_key]['sale_regime']))
        return orders, message_data

    @api.model
    def _process_order(self, pos_order, draft, existing_order):
        order = super(PosOrder, self)._process_order(pos_order, draft, existing_order)
        self.browse(order).register_pos_sales()
        return order

    def register_pos_sales(self):
        order = self
        data_dict = {}
        redeem_coupon_amt = 0.0
        redeem_predetermined_tax_coupon_amt = 0.0
        redeem_zakl_dan1 = 0.0
        redeem_dan1 = 0.0
        redeem_zakl_dan2 = 0.0
        redeem_dan2 = 0.0
        redeem_zakl_dan3 = 0.0
        redeem_dan3 = 0.0
        eet_message_obj = self.env['eet.message']
        tz = pytz.timezone(self.env.user.tz or 'UTC')
        data_dict['dat_trzby'] = tz.localize(order.date_order).replace(microsecond=0).isoformat()
        data_dict['id_pokl'] = order.session_id.name
        data_dict['porad_cis'] = order.name
        lines_with_coupon = order.lines.filtered('product_id.coupon')
        predetermined_tax_coupon_lines = lines_with_coupon.filtered('tax_ids')
        no_tax_coupon_lines = lines_with_coupon - predetermined_tax_coupon_lines
        travel_service_line_ids = order.lines.filtered('product_id.travel_service')
        taxed_pos_line_ids = order.lines.filtered('tax_ids') - travel_service_line_ids - lines_with_coupon
        used_goods_line_ids = taxed_pos_line_ids.filtered('product_id.used_goods')
        taxed_pos_line_ids -= used_goods_line_ids
        untaxed_pos_line_ids = order.lines - taxed_pos_line_ids - travel_service_line_ids - used_goods_line_ids \
            - lines_with_coupon
        direct_repr_sales = taxed_pos_line_ids.filtered(lambda line: line.product_id.direct_representation)
        normal_sales = taxed_pos_line_ids - direct_repr_sales
        if no_tax_coupon_lines:
            for line in no_tax_coupon_lines:
                if line.qty > 0.0:
                    no_tax_coupon_dict = data_dict.copy()
                    no_tax_coupon_dict['dic_popl'] = self.env.user.company_id.vat or ''
                    no_tax_coupon_dict['id_provoz'] = str(order.session_id.config_id.estd_reg_no) or ''
                    no_tax_coupon_dict['rezim'] = self.env.user.company_id.sale_regime or ''
                    no_tax_coupon_dict['celk_trzba'] = format(line.price_subtotal_incl, '.2f')
                    no_tax_coupon_dict['urceno_cerp_zuct'] = format(line.price_subtotal_incl, '.2f')
                    eet_message_obj.render(order, no_tax_coupon_dict)
                else:
                    redeem_coupon_amt += abs(line.price_subtotal_incl)
        if predetermined_tax_coupon_lines:
            for line in predetermined_tax_coupon_lines:
                if line.qty > 0.0:
                    tax_coupon_dict = data_dict.copy()
                    tax_coupon_dict['dic_popl'] = self.env.user.company_id.vat or ''
                    tax_coupon_dict['id_provoz'] = str(order.session_id.config_id.estd_reg_no) or ''
                    tax_coupon_dict['rezim'] = self.env.user.company_id.sale_regime or ''
                    tax_coupon_dict = self.set_tax_base_and_vat(line, tax_coupon_dict)
                    tax_coupon_dict['urceno_cerp_zuct'] = format(line.price_subtotal_incl, '.2f')
                    eet_message_obj.render(order, tax_coupon_dict)
                else:
                    redeem_predetermined_tax_coupon_amt += abs(line.price_subtotal_incl)
                    for tax in line.tax_ids:
                        if tax.rate_type == 'basic':
                            redeem_zakl_dan1 += abs(line.price_subtotal)
                            redeem_dan1 += tax._compute_amount(abs(line.price_subtotal),
                                line.price_unit, quantity=abs(line.qty))
                        if tax.rate_type == 'first_reduced':
                            redeem_zakl_dan2 += abs(line.price_subtotal)
                            redeem_dan2 += tax._compute_amount(abs(line.price_subtotal),
                                line.price_unit, quantity=abs(line.qty))
                        if tax.rate_type == 'second_reduced':
                            redeem_zakl_dan3 += abs(line.price_subtotal)
                            redeem_dan3 += tax._compute_amount(abs(line.price_subtotal),
                                line.price_unit, quantity=abs(line.qty))
        coupon_dict = {
            'redeem_coupon_amt': redeem_coupon_amt,
            'redeem_predetermined_tax_coupon_amt': redeem_predetermined_tax_coupon_amt,
            'redeem_zakl_dan1': redeem_zakl_dan1,
            'redeem_dan1': redeem_dan1,
            'redeem_zakl_dan2': redeem_zakl_dan2,
            'redeem_dan2': redeem_dan2,
            'redeem_zakl_dan3': redeem_zakl_dan3,
            'redeem_dan3': redeem_dan3,
        }
        if used_goods_line_ids:
            used_goods_dict = data_dict.copy()
            total_sales = 0.0
            amt_basic = 0.0
            amt_first_reduced = 0.0
            amt_second_reduced = 0.0
            used_goods_dict['dic_popl'] = self.env.user.company_id.vat or ''
            used_goods_dict['id_provoz'] = str(order.session_id.config_id.estd_reg_no) or ''
            used_goods_dict['rezim'] = self.env.user.company_id.sale_regime or ''
            for line in used_goods_line_ids:
                total_sales += line.price_subtotal_incl
                for tax in line.tax_ids:
                    if tax.rate_type == 'basic':
                        amt_basic += line.price_subtotal_incl
                    elif tax.rate_type == 'first_reduced':
                        amt_first_reduced += line.price_subtotal_incl
                    elif tax.rate_type == 'second_reduced':
                        amt_second_reduced += line.price_subtotal_incl
            used_goods_dict['celk_trzba'] = format(total_sales, '.2f')
            used_goods_dict['pouzit_zboz1'] = format(amt_basic, '.2f')
            used_goods_dict['pouzit_zboz2'] = format(amt_first_reduced, '.2f')
            used_goods_dict['pouzit_zboz3'] = format(amt_second_reduced, '.2f')
            if redeem_coupon_amt:
                used_goods_dict['cerp_zuct'] = format(redeem_coupon_amt, '.2f')
            eet_message_obj.render(order, used_goods_dict)
        if travel_service_line_ids:
            travel_dict = data_dict.copy()
            total_sales = 0.0
            travel_dict['dic_popl'] = self.env.user.company_id.vat or ''
            travel_dict['id_provoz'] = str(order.session_id.config_id.estd_reg_no) or ''
            travel_dict['rezim'] = self.env.user.company_id.sale_regime or ''
            for line in travel_service_line_ids:
                total_sales += line.price_subtotal_incl
            travel_dict['celk_trzba'] = format(total_sales, '.2f')
            travel_dict['cest_sluz'] = format(total_sales, '.2f')
            if redeem_coupon_amt:
                travel_dict['cerp_zuct'] = format(redeem_coupon_amt, '.2f')
            eet_message_obj.render(order, travel_dict)
        if direct_repr_sales:
            for supplier in direct_repr_sales.mapped('product_id').mapped('auth_taxpayer_id'):
                same_auth_sales = direct_repr_sales.filtered(lambda line: line.product_id.auth_taxpayer_id == supplier)
                direct_dict = data_dict.copy()
                direct_dict['dic_popl'] = supplier.vat or ''
                direct_dict['id_provoz'] = str(supplier.estd_reg_no) or ''
                direct_dict['rezim'] = supplier.sale_regime or ''
                direct_dict = self.set_tax_base_and_vat(same_auth_sales, direct_dict, coupon_dict=coupon_dict)
                cert_attachment = self.env['ir.attachment'].search([
                    ('res_id', '=', supplier.id),
                    ('res_model', '=', 'res.partner'),
                    ('mimetype', '=', 'application/x-pkcs12')], limit=1)
                cert_path = cert_attachment._full_path(cert_attachment.store_fname or '')
                eet_message_obj.render(order, direct_dict,
                    cert_path=cert_path, cert_password=supplier.cert_password or '')
        if normal_sales:
            normal_dict = data_dict.copy()
            normal_sales_with_auth = normal_sales.filtered(lambda line: line.product_id.auth_taxpayer_id)
            normal_sales -= normal_sales_with_auth
            normal_dict['dic_popl'] = self.env.user.company_id.vat or ''
            normal_dict['id_provoz'] = str(order.session_id.config_id.estd_reg_no) or ''
            normal_dict['rezim'] = self.env.user.company_id.sale_regime or ''
            if normal_sales_with_auth:
                for supplier in normal_sales_with_auth.mapped('product_id').mapped('auth_taxpayer_id'):
                    with_auth_dict = normal_dict.copy()
                    same_normal_sales = normal_sales_with_auth.filtered(\
                        lambda line: line.product_id.auth_taxpayer_id == supplier)
                    with_auth_dict = self.set_tax_base_and_vat(same_normal_sales, with_auth_dict, coupon_dict=coupon_dict)
                    with_auth_dict['dic_poverujiciho'] = supplier.vat or ''
                    eet_message_obj.render(order, with_auth_dict)
            if normal_sales:
                normal_dict = self.set_tax_base_and_vat(normal_sales, normal_dict, coupon_dict=coupon_dict)
                eet_message_obj.render(order, normal_dict)
        if untaxed_pos_line_ids:
            untaxed_dict = data_dict.copy()
            total_sales = 0.0
            untaxed_dict['dic_popl'] = self.env.user.company_id.vat or ''
            untaxed_dict['id_provoz'] = str(order.session_id.config_id.estd_reg_no) or ''
            untaxed_dict['rezim'] = self.env.user.company_id.sale_regime or ''
            for line in untaxed_pos_line_ids:
                total_sales += line.price_subtotal_incl
            untaxed_dict['celk_trzba'] = format(total_sales, '.2f')
            if redeem_coupon_amt:
                untaxed_dict['cerp_zuct'] = format(redeem_coupon_amt, '.2f')
            eet_message_obj.render(order, untaxed_dict)


class PosConfig(models.Model):
    _inherit = 'pos.config'

    estd_reg_no = fields.Integer('Establishment Reg. No.')
