from ssl import SSLError
from fastapi import FastAPI, HTTPException,Request
from fastapi.templating import Jinja2Templates # To generate front end for the FastAPI backend 
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, validator # To validate user request 
from pydantic.networks import EmailStr, AnyHttpUrl # To validate email and URL in specific user input fields
import re
import random
import string
import shutil
import fileinput
import sys
import pdfkit
from bs4 import BeautifulSoup # To check if a user input is HTML
from  urlextract import URLExtract # To extract URLs from user input 
import tldextract # To extract domains from URLs in user input 
from ipaddress import IPv4Address # To validate if a user input has specific IP address
from socket import gethostbyname, gaierror # To resolve domains in user input
import requests # To check HTTP redirection on URLs in user input
from bleach import clean

app = FastAPI()

templates = Jinja2Templates(directory="templates")

class Item(BaseModel):
    name: str
    job: str
    email: EmailStr
    portfolio: AnyHttpUrl
    phone: str
    twitter: str

    @validator("phone")
    def phone_validation(cls, v):
    # logger.debug(f"phone in 2 validator:{v}")ter
        regex = r"^(\+)[1-9][0-9\-\(\)\.]{9,15}$"
        if v and not re.search(regex, v, re.I):
            raise ValueError("Phone Number Invalid.")
        return v

    class Config:
        orm_mode = True
        use_enum_values = True

@app.get("/", response_class=HTMLResponse)
async def form(request: "Request"):
    context={'request': request}
    return templates.TemplateResponse("create_card.html", context)

@app.post("/create-card", response_class=FileResponse)
async def create_card(card: Item, request: "Request"):
    context={'request': request}
    ## Generating unique ID to append to final business card. This is to ensure every user has unique file.
    if bool(BeautifulSoup(card.twitter, "html.parser").find()):
        print("HTML Detected")
        ssrf_blacklist(card.twitter)

    unique_id = ''.join(random.choices(string.ascii_lowercase, k=15))
    final_business_card_html_file = "business-card-final-"+unique_id+".html"
    final_business_card_pdf_file = "business-card-final-"+unique_id+".pdf"

    shutil.copyfile("business-card-template.html", final_business_card_html_file)
    
    def replaceAll(file,searchExp,replaceExp):
        for line in fileinput.input(file, inplace=1):
            if searchExp in line:
                line = line.replace(searchExp,replaceExp)
            sys.stdout.write(line)

    replaceAll(final_business_card_html_file,'PERSON_NAME',clean(card.name))
    replaceAll(final_business_card_html_file,'PERSON_JOB', clean(card.job))
    replaceAll(final_business_card_html_file,'EMAIL_ADDRESS', clean(card.email))
    replaceAll(final_business_card_html_file,'PORTFOLIO', clean(card.portfolio))
    replaceAll(final_business_card_html_file,'MOBILE_NUMBER', clean(card.phone))
    replaceAll(final_business_card_html_file,'TWITTER_HANDLE', card.twitter)
    try:
        pdfkit.from_file(final_business_card_html_file,
        final_business_card_pdf_file)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Malformed Input Detected")
    #save_pdf(final_business_card_pdf_file, "file://"+getcwd()+"/"+final_business_card_html_file)

    headers = {'Content-Disposition': 'attachment; filename="business-card.pdf"'}
    #return Response(final_business_card_pdf_file, headers=headers, media_type='application/pdf')

    return FileResponse(final_business_card_pdf_file, media_type="application/pdf", headers={
             'Content-Disposition': 'inline;filename="business-card.pdf"' })

def ssrf_blacklist(user_input):
    if "169.254.169.254" in user_input:
        raise HTTPException(status_code=400, detail="Malicious IP Detected!!")
        #return {"Error": "Malicious IP Detected!!"}
    else: 
        extractor = URLExtract()
        urls_in_payload = extractor.find_urls(user_input, only_unique=True,check_dns=True)
        print("URLs before", urls_in_payload)

        ipPattern = re.compile("(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)")
        ip_addresses_in_payload = []
        for url in urls_in_payload:
            #print("url is " + url)
            ip = re.findall(ipPattern,url)
            if ip:
                for i in ip:
                    ip_addresses_in_payload.append(i)
                    #urls_in_payload.remove(url)
        print(ip_addresses_in_payload)

        ## Check if IP Addresses match 169.254.169.254
        for ip in ip_addresses_in_payload:
            urls_in_payload.remove(ip)
            if IPv4Address("169.254.169.254") == IPv4Address(ip):
                raise HTTPException(status_code=400, detail="Malicious IP Detected!!")

        print("URLs after", urls_in_payload)

        ## Extract and remove any IP addresses
        domains_in_payload =  []
        for url in urls_in_payload:
            ext = tldextract.extract(url)
            domains_in_payload.append('.'.join(part for part in ext if part))
        print(domains_in_payload)

        ## Resolve domains and check if they point to 169.254.169.254
        try:
            for domain in domains_in_payload:
                #print("Domain is ", domain)
                a_record = gethostbyname(domain)
                print("A Record is ", a_record)
                if IPv4Address("169.254.169.254") == IPv4Address(a_record):
                    #print("Dangerous resolution")
                    raise HTTPException(status_code=400, detail="Malicious Resolution Detected!!")
        except gaierror as e:
            print(e)
        
        ## Check if domains have 302/301 resolution
        for domain in domains_in_payload:
            print("Domain is", domain)
            try:
                http_response = requests.get("http://"+domain,  allow_redirects=False)
                print(http_response)
                if http_response.status_code == 301 or http_response.status_code == 302 or http_response.status_code == 304:
                        raise HTTPException(status_code=400, detail="Malicious Redirection Detected!!")
                https_response = requests.get("https://"+domain,  allow_redirects=False)
            
                if https_response.status_code == 301 or http_response.status_code == 302 or http_response.status_code == 304:
                        raise HTTPException(status_code=400, detail="Malicious Redirection Detected!!")
            except SSLError:
                        raise HTTPException(status_code=400, detail="Something went wrong with the SSL")
                    
