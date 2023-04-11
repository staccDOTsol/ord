const fs = require('fs')
const axios = require('axios')
const PromisePool = require('@supercharge/promise-pool').PromisePool
const nfts = JSON.parse(fs.readFileSync('nfts.json').toString())
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

setTimeout(async () => {
const nftsWithUri = nfts.filter((nft) => nft.offChainMetadata.uri != undefined)
console.log(nftsWithUri.length)
const pool = new PromisePool(1)
await pool.for(nftsWithUri).process(async (nft) => {
console.log(nft)
    if (nft.offChainMetadata.uri != undefined) {
        console.log(nft.offChainMetadata.uri )
        
        let image = await axios.get(nft.offChainMetadata.metadata.image, { responseType: 'arraybuffer' })
        fs.writeFileSync(`images/${nft.onChainMetadata.metadata.mint}.png`, image.data)
        fs.writeFileSync(`metadata/${nft.onChainMetadata.metadata.mint}.json`, JSON.stringify(nft.offChainMetadata))
        }
   
})
}, 1)