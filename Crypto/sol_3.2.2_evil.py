#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
           C��_w4'[Q6|�o�����s�bdZby2p��K��R�;��k� �K&O: %c+<Ymv�.N9�9%Ǩ�NRW^^4�5���L�
-ypgP��o3�Z㦢	J���?�P���Xv�rDQ�"""
from hashlib import sha256
if sha256(blob).hexdigest() == '7ae3afe0291a979c5b90388e1df9aa9c8c09ea9bdf7bc771a099aecafb64575b':
    print "I come in peace."
else:
    print "Prepare to be destroyed!"
