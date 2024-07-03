# DA-ODR-DNSSEC-SYNC
Directadmin to Open Domain Registry DNSSEC Synchronisation script

With this script you can sync your DS records automatically to ODR.

- It supports one ODR Account per Reseller.
- There is a seperate file where you can add the credentials per reseller and also define the admin username if it is not the default.
- A domain needs to belong to a user that belongs to a reseller for this to work.
- The way it functions:
  - It will check if DA has a valid signed zone,
  - extracts the keys from the keyfiles,
  - checks if odr has existing keys.
  - Checks if they are the same.
  - If they are not the same it will try to update them for you.
  - It will create a notification for the reseller on succes
  - It will create a notification for the admin and reseller on failure
  - It will log all output to /var/log/da-ord-dnssec-sync.log comment line 24 & 27 if you don't want to log it. 

**Questions? Open an issue!**
