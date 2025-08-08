from flask import Flask, render_template, request, redirect, session, url_for, flash,jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import pandas as pd
from flask_mail import Mail, Message
import secrets
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from bson import ObjectId
# from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import stripe
import os
from web3 import Web3
import smtplib
import threading, time


app = Flask(__name__, static_url_path='/static')
app.secret_key = 'your_secret_key'

##############################################################
import json

ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

deployed_contract_address = "0x2787A20520081C1026F53D1FBF6104666c27731F"  # Replace with actual address

with open('build/contracts/CropApplication.json') as f:
    contract_json = json.load(f)

contract_abi = contract_json['abi']
contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)



# Fetch all past events
events = contract.events.YourEventName.create_filter(fromBlock="latest").get_all_entries()

print(events)
