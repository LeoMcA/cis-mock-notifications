#!/bin/sh

curl -H "Content-Type: application/json" -X POST -d @notification.json http://localhost:4567/
