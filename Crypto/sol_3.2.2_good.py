#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
           C��_w4'[Q6|�o����As�bdZby2p��K��R�;��k� HK&O: %c+<Ymv��N9�9%Ǩ�NRW^^4�5��'L�
-ypgP��o3�Z㦢	J��?�P���Xv��DQ�"""
from hashlib import sha256
if sha256(blob).hexdigest() == '7ae3afe0291a979c5b90388e1df9aa9c8c09ea9bdf7bc771a099aecafb64575b':
    print "I come in peace."
else:
    print "Prepare to be destroyed!"
