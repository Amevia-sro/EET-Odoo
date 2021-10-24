# -*- coding: utf-8 -*-

{
    'name': 'EET (CZ)',
    'version': '1.0',
    'author': 'Amevia s.r.o.',
    "website" : "https://www.amevia.eu",
    'summary': 'Registration of Sales',
    'description': """
Registration of Sales
=====================
The module registers sales with Czech Republic authority, and fetches FIK in order to set
on the printed receipt.

Install the following python package:
    1. pyOpenSSL (pip3 install pyOpenSSL)
    
Configure the absolute path as value showing location of the certificate situated in server into the system parameter with key pkcs12.
    """,
    'category': 'Point Of Sale',
    'depends': ['point_of_sale', 'Czech_l10n_cz'],
    'data': [
        'security/revenue_data_message_security.xml',
        'security/ir.model.access.csv',
        'wizard/connection_test_view.xml',
        'views/connection_test_menuitem.xml',
        'views/product_view.xml',
        'views/res_partner_view.xml',
        'views/res_company_view.xml',
        'views/data_message_menuitem.xml',
        'views/data_message_view.xml',
        'views/point_of_sale.xml',
        'views/pos_config_view.xml',
        'views/eet_message_view.xml',
        'data/payment_data.xml',
        'data/certificate_details.xml',
    ],
    'qweb': ['static/src/xml/pos.xml'],
    'external_dependencies': {'python': ['OpenSSL']},
    'installable': True,
    'application': True,
    'price': 0.00,
    'currency': 'EUR',
    'auto_install': False
}

