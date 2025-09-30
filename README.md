# Marketing Defect Scripts

Some JS scripts created by ChatGPT, edited by HeroDevs.

The goal of these scripts is to find the list of vulnerabilities that have been addressed in prior versions of OSS package

## Catalog Scrape

Request every page of the catalog API and distill it down to a list of all OSS fork points. Only the fork point that is the highest is taken.

```
node catalog_scrape.js
```

## OSV Scrape

Requires catalog_scrape.js to have been run prior to this. Looks at all the OSS forkpoints from NES products, and queries OSV for each package and finds all vulns that affect versions less than or equal to the NES forkpoint.

```
node osv_scrape.js
```
