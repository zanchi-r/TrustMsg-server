#!/bin/bash
openssl req -x509 -newkey rsa:2048 -keyout ssl.key -out ssl.cert -days 365
