const axios = require('axios')
const fs = require('fs')
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
let mintlist = JSON.parse(fs.readFileSync('mintlist.json').toString())
var url = `https://api.helius.xyz/v1/mintlist?api-key=3879e922-b15c-4bb4-ad65-c2523590ea3b`
const getMintlist = async () => {
    const { data } = await axios.post(url, {
        "query": {
            // ABC collection
            "verifiedCollectionAddresses":["6XxjKYFbcndh2gDcsUrmZgVEsoDxXMnfsaGY6fpTJzNr"]
        },
        "options": {

            "limit": 10000
        }
    });
    mintlist.push(...data.result.map((item) => item.mint))
    console.log(mintlist.length)
    fs.writeFileSync('mintlist.json', JSON.stringify(mintlist))
}
;
console.log(mintlist.length)
 url = `https://api.helius.xyz/v0/token-metadata?api-key=3879e922-b15c-4bb4-ad65-c2523590ea3b `
let nfts =[]// JSON.parse(fs.readFileSync('nfts.json').toString())
console.log(nfts.length)
let c = nfts.length / 100
const getMetadata = async () => {
    for (var i = 1; i <= mintlist.length/100; i ++) {
        if (i <= c) {
            continue
        }
    let resultArray = mintlist.slice((i-1)*100, i*100)
    if (i == mintlist.length/100) {
        resultArray = mintlist.slice((i-1)*100, mintlist.length)
    }

    const { data } = await axios.post(url, {
        mintAccounts: resultArray,
        includeOffChain: true,
        disableCache: false,
        includeTokenMetadata: true,
        includeTokenAccountMetadata: true,
        includeTokenAccountBalance: true,
        includeTokenAccountOwner: true,
        includeTokenAccountMint: true,
        includeTokenAccountRentExemptReserve: true,
    });
    nfts.push(...data)
    console.log(nfts.length)
    fs.writeFileSync('nfts.json', JSON.stringify(nfts))
}
}


getMetadata();