#!/usr/bin/env python3
'''Module for filtered_logger'''
import os
import mysql.connector as connector
from mysql.connector import Error
import re
from typing import List
import logging

PII_FIELDS = ('password', 'ssn', 'name', 'email', 'phone')


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        '''Init Function for RedactingFormatter'''
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        '''Formatter function to hide sensitive data'''
        record.msg = filter_datum(
            self.fields, self.REDACTION, record.msg, self.SEPARATOR)
        return super().format(record)


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:  # nopep8
    '''Function to filter out sensitive fields'''
    pattern = fr'({"|".join(fields)})=[^{separator}]+'
    return re.sub(pattern, fr'\1={redaction}', message)


def get_logger() -> logging.Logger:
    '''Function that returns a logger'''
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    style = RedactingFormatter(PII_FIELDS)
    handler.setFormatter(style)
    logger.addHandler(handler)
    return logger


def get_db() -> connector.connection.MySQLConnection:
    '''Function to connect to database'''
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    hol_db = os.getenv("PERSONAL_DATA_DB_NAME")

    try:
        connection = connector.connect(host=host, database=hol_db, username=user, password=password)  # nopep8
        return connection
    except Error as e:
        print('Error:', e)


def main():
    '''Main function to read users'''
    log = get_logger()
    connection = get_db()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users")
    for row in cursor.fetchall():
        message = '; '.join([f'{k}={v}' for k, v in row.items()])
        log.info(message)
    cursor.close()
    connection.close()


if __name__ == '__main__':
    main()
