#!/usr/bin/env python3
'''Module for filtered_logger'''
import re

def filter_datum(fields, redaction, message, separator):
    '''Function to filter out sensitive fields'''
    pattern = fr'({"|".join(fields)})=[^{separator}]+'
    return re.sub(pattern, fr'\1={redaction}', message)
