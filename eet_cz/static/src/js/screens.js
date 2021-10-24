odoo.define('eet_cz.screens', function (require) {
"use strict";

var screens = require('point_of_sale.screens');

screens.PaymentScreenWidget.include({
    finalize_validation: function() {
        var self = this;
        var order = this.pos.get_order();

        if (order.is_paid_with_cash() && this.pos.config.iface_cashdrawer) { 

                this.pos.proxy.printer.open_cashbox();
        }

        order.initialize_validation_date();
        order.finalized = true;

        if (order.is_to_invoice()) {
            var invoiced = this.pos.push_and_invoice_order(order);
            this.invoicing = true;

            invoiced.catch(this._handleFailedPushForInvoice.bind(this, order, false));

            invoiced.then(function (server_ids) {
                self.invoicing = false;
                var post_push_promise = [];
                post_push_promise = self.post_push_order_resolve(order, server_ids);
                post_push_promise.then(function () {
                        // self.gui.show_screen('receipt');
                }).catch(function (error) {
                    // self.gui.show_screen('receipt');
                    if (error) {
                        self.gui.show_popup('error',{
                            'title': "Error: no internet connection",
                            'body':  error,
                        });
                    }
                });
            });
        } else {
            var ordered = this.pos.push_order(order);
            if (order.wait_for_push_order()){
                var server_ids = [];
                ordered.then(function (ids) {
                  server_ids = ids;
                }).finally(function() {
                    var post_push_promise = [];
                    post_push_promise = self.post_push_order_resolve(order, server_ids);
                    post_push_promise.then(function () {
                            // self.gui.show_screen('receipt');
                        }).catch(function (error) {
                          // self.gui.show_screen('receipt');
                          if (error) {
                              self.gui.show_popup('error',{
                                  'title': "Error: no internet connection",
                                  'body':  error,
                              });
                          }
                        });
                  });
            }
            else {
              // self.gui.show_screen('receipt');
            }

        }

    },
});
});

