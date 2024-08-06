import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
import time
import sys

if len(sys.argv) != 2:
    print("Usage: python script.py [firewall_serial_number]")
    sys.exit(1)

firewall_serial_number = sys.argv[1]

INEEDIN_SECRET_LINK_CSP="https://letmein.panw.app/connect/getlink/xdr-labs-csp-otp/aUiAXYm7hM2-xQVbjRBLKZu__4Y6hZ_CQOpUxpUM1nI/"
response= requests.get(INEEDIN_SECRET_LINK_CSP,verify=False)
website_url=response.text.replace('"',"")
print("Selenium CSP UI automation begins")

# Configure Chrome options & Initialize the Chrome webdriver
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage')
# driver = webdriver.Chrome(options=chrome_options)  ##### UNCOMMENT

#### NEW WEBDRIVER MANAGER PIECE
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
import os
os.environ['WDM_SSL_VERIFY'] = '0'
driver = webdriver.Chrome(options=chrome_options,service=ChromeService(ChromeDriverManager(driver_version="126").install()))
######
# Open the website & wait for the page to be fully loaded
driver.get(website_url)
wait = WebDriverWait(driver, 60)
wait.until(EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Generate OTP')]")))

# Click Radio button
radio_button = driver.find_element(By.XPATH,"//span[contains(text(), 'Next-Gen Firewall')]/preceding-sibling::span[contains(@class,'ant-radio')]")
driver.execute_script("arguments[0].click();", radio_button)
# radio_button.click()

# Click Next button & wait for serial number searchbo
next_button_parent = driver.find_element(By.XPATH, "//*[contains(text(), 'Next')]/ancestor::button[contains(@type, 'submit')]")
driver.execute_script("arguments[0].click();", next_button_parent)
# next_button_parent.click()
wait.until(EC.presence_of_element_located((By.ID, "SerialNumber")))

# Type the serial number in the searchbox & hit enter # FIXME fails sometimes
time.sleep(5)
search_box = driver.find_element(By.ID, "SerialNumber")
search_box.send_keys(firewall_serial_number)
search_box.send_keys(Keys.ENTER)

# CLick Generate OTP button
generate_otp_button = driver.find_element(By.XPATH,"//span[contains(text(), 'Generate OTP')]/ancestor::button[contains(@type, 'submit')]")
driver.execute_script("arguments[0].click();", generate_otp_button)
# generate_otp_button.click()
wait.until(EC.presence_of_element_located((By.XPATH, "//dt[contains(text(), 'Password:')]/following-sibling::dd")))

# Find the <dd> tag after the <dt> tag with text "Password:"
password_dd = driver.find_element(By.XPATH, "//dt[contains(text(), 'Password:')]/following-sibling::dd")

# Get the text of the <dd> tag
password_value = password_dd.text
print("Password:", password_value)

# Close the browser session
driver.quit()
