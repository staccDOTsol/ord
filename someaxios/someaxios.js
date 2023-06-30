
const { Client } = require('@notionhq/client');

const notion = new Client({ auth: "secret_eLmsgKPioTFtSJqXujs4QPq2C0oSrQrSD8xeWW9PQO3" });

(async () => {
    let content = ""
  const response = await notion.search({
    query: '',
    sort: {
      direction: 'ascending',
      timestamp: 'last_edited_time'
    },
  });
  for (var r of response.results){
    if (r.object == 'page'){
        let pageId = r.id 
       
  const response = await notion.blocks.children.list({
    block_id: pageId,
    page_size: 50,
  });
  for (var r2 of response.results){
    
    for (var key of Object.keys(r2)){
        if (key == 'child_page'){

  const response2 = await notion.blocks.children.list({
    block_id: r2['id'],
    page_size: 50,
  });
  
  for (var r3 of response2.results){
    
    for (var key2 of Object.keys(r3)){

        try {
            for (var tt of r3[key2].rich_text){
            content+=(tt.text.content+'\n')
            }
        } catch (err){

        }
    }
        }
        try {
            console.log(r2[key].rich_text[0].text.content)
        } catch (err){

        }
    }
}
  }


  }
  }
  console.log(content)
})();