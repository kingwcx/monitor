#!/usr/bin/python
# -*- coding: utf-8 -*-
import pygeoip
import geoip2.database
import os

pre_path = os.path.dirname(os.getcwd())
gi = geoip2.database.Reader(pre_path + "/datas/GeoLite2-City/GeoLite2-City.mmdb")

def printRecord(tgt):
    data = gi.city(tgt)
    print("IP Address: ", tgt)
    print("Country:", data.country.name)
    print("Subdivisions: ", data.subdivisions.most_specific.name)
    print("City: ", data.city.n+ame)
    print("Latitude: ", data.location.latitude)
    print("Longitude: ", data.location.longitude)
    return data.country.name

tgt = '180.160.220.214'
printRecord(tgt)

