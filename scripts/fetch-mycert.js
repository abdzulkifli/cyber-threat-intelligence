const fs = require('fs');
const path = require('path');

const OUT = path.join(process.cwd(), 'data', 'mycert.json');
const OFFICIAL_URL = 'https://mycert.org.my/portal/index';
const DIRECT_URLS = [
  'https://mycert.org.my/portal/index',
  'https://www.mycert.org.my/portal/index'
];

// Jina Reader is used only as a transport fallback when MyCERT's Cloudflare
// blocks GitHub-hosted runners. MyCERT remains the authoritative source.
const READER_URLS = DIRECT_URLS.map(url => `https://r.jina.ai/${url}`);

const sleep = ms => new Promise(r => setTimeout(r, ms));
function nowIso(){ return new Date().toISOString(); }

function decodeHtml(s=''){
  return String(s)
    .replace(/&nbsp;/gi,' ')
    .replace(/&amp;/gi,'&')
    .replace(/&quot;/gi,'"')
    .replace(/&#39;|&apos;/gi,"'")
    .replace(/&lt;/gi,'<')
    .replace(/&gt;/gi,'>')
    .replace(/&#(\d+);/g,(_,n)=>String.fromCharCode(Number(n)));
}

function stripHtml(s=''){
  return decodeHtml(String(s)
    .replace(/<script[\s\S]*?<\/script>/gi,' ')
    .replace(/<style[\s\S]*?<\/style>/gi,' ')
    .replace(/<[^>]+>/g,' ')
    .replace(/\s+/g,' ')
    .trim());
}

function normalizeUrl(href, base=OFFICIAL_URL){
  try {
    const u = new URL(decodeHtml(href), base);
    // Never expose the reader-proxy URL as the advisory source URL.
    if (u.hostname === 'r.jina.ai') return OFFICIAL_URL;
    return u.href;
  } catch {
    return OFFICIAL_URL;
  }
}

function parseDate(s){
  const text = String(s || '');
  let m = text.match(/(\d{1,2})[-\/]([01]?\d)[-\/](20\d{2})/);
  if(m){
    const [,d,mo,y] = m;
    return `${y}-${String(mo).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
  }
  m = text.match(/(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(20\d{2})/i);
  if(m){
    const months={jan:1,feb:2,mar:3,apr:4,may:5,jun:6,jul:7,aug:8,sep:9,oct:10,nov:11,dec:12};
    const mo=months[m[2].slice(0,3).toLowerCase()];
    return `${m[3]}-${String(mo).padStart(2,'0')}-${String(m[1]).padStart(2,'0')}`;
  }
  return null;
}

function classify(title){
  const t=String(title||'').toLowerCase();
  if(t.includes('ransomware')) return 'RANSOMWARE';
  if(t.includes('phishing')||t.includes('scam')) return 'PHISHING';
  if(t.includes('malware')||t.includes('botnet')) return 'MALWARE';
  if(t.includes('alert')) return 'ALERT';
  if(t.includes('vulnerab')||t.includes('exploit')||t.includes('remote code')||t.includes('rce')) return 'VULNERABILITY';
  return 'ADVISORY';
}

function severity(title){
  const t=String(title||'').toLowerCase();
  if(t.includes('critical')||t.includes('actively exploited')||t.includes('active exploitation')||t.includes('ransomware')) return 'CRITICAL SIGNAL';
  if(t.includes('high-severity')||t.includes('high severity')||t.includes('multiple vulnerab')) return 'HIGH SIGNAL';
  return '';
}

function buildItem(rawText, href=OFFICIAL_URL, dateHint=null){
  const clean = stripHtml(rawText)
    .replace(/^#+\s*/,'')
    .replace(/^[-*•]\s*/,'')
    .replace(/^\s*\[?\d{1,2}[-\/]\d{1,2}[-\/]20\d{2}\]?\s*/,'')
    .trim();
  const id = (clean.match(/MA-\d+\.\d+/i)||[])[0];
  if(!id) return null;
  const title = clean.replace(/^.*?(MA-\d+\.\d+\s*:\s*)/i, '$1').trim();
  const cves=[...new Set((title.match(/CVE-\d{4}-\d{4,7}/gi)||[]).map(x=>x.toUpperCase()))];
  return {
    id:id.toUpperCase(),
    date:parseDate(rawText)||dateHint||null,
    title,
    url:normalizeUrl(href),
    type:classify(title),
    severity:severity(title),
    cves
  };
}

function dedupeSort(items){
  const byId = new Map();
  for(const item of items){
    if(!item?.id) continue;
    const previous=byId.get(item.id);
    if(!previous || (!previous.date && item.date) || (previous.url===OFFICIAL_URL && item.url!==OFFICIAL_URL)) byId.set(item.id,item);
  }
  return [...byId.values()]
    .sort((a,b)=>String(b.date||'').localeCompare(String(a.date||'')) || b.id.localeCompare(a.id))
    .slice(0,40);
}

function extractFromHtml(html, baseUrl){
  const items=[];
  const plain=stripHtml(html);

  // Find dates that appear close to advisory IDs in page text.
  const dateById=new Map();
  const datePatterns=[
    /(\d{1,2}[-\/]\d{1,2}[-\/]20\d{2})\s+(MA-\d+\.\d+)/gi,
    /(MA-\d+\.\d+)[\s\S]{0,100}?(\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+20\d{2})/gi
  ];
  for(const re of datePatterns){
    let d;
    while((d=re.exec(plain))){
      const id=(d[1].toUpperCase().startsWith('MA-')?d[1]:d[2]).toUpperCase();
      const date=parseDate(d[1].toUpperCase().startsWith('MA-')?d[2]:d[1]);
      if(date) dateById.set(id,date);
    }
  }

  const anchorRe=/<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while((m=anchorRe.exec(html))){
    const text=stripHtml(m[2]);
    const id=(text.match(/MA-\d+\.\d+/i)||[])[0];
    if(!id) continue;
    const item=buildItem(text, normalizeUrl(m[1],baseUrl), dateById.get(id.toUpperCase())||null);
    if(item) items.push(item);
  }

  // Fallback for pages where advisory titles are not anchors.
  const lineRe=/(?:\[?(\d{1,2}[-\/]\d{1,2}[-\/]20\d{2})\]?\s*)?(MA-\d+\.\d+\s*:\s*MyCERT\s+(?:Advisory|Alert)[^\n]{4,260})/gi;
  let x;
  while((x=lineRe.exec(plain))){
    const item=buildItem(`${x[1]||''} ${x[2]}`,baseUrl,parseDate(x[1]));
    if(item) items.push(item);
  }
  return dedupeSort(items);
}

function extractFromMarkdown(md){
  const items=[];
  const text=String(md||'').replace(/\r/g,'');

  // Reader commonly returns markdown links. Capture the visible advisory title
  // and keep any original mycert.org.my URL if present.
  const linkRe=/\[([^\]]*MA-\d+\.\d+[^\]]*)\]\((https?:\/\/[^)\s]+)\)/gi;
  let m;
  while((m=linkRe.exec(text))){
    const item=buildItem(m[1],m[2]);
    if(item) items.push(item);
  }

  // Capture plain markdown headings / bullets such as:
  // [26-07-2026] MA-1479.072026: MyCERT Advisory - ...
  // #### MA-1479.072026: MyCERT Advisory - ...
  const lines=text.split('\n').map(l=>l.trim()).filter(Boolean);
  for(let i=0;i<lines.length;i++){
    const line=lines[i];
    if(!/MA-\d+\.\d+/i.test(line)) continue;
    if(!/MyCERT\s+(?:Advisory|Alert)|MA-\d+\.\d+\s*:/i.test(line)) continue;

    let date=parseDate(line);
    // Reader often puts the date on the next bullet below the heading.
    if(!date){
      for(let j=i+1;j<Math.min(lines.length,i+5);j++){
        const candidate=parseDate(lines[j]);
        if(candidate){ date=candidate; break; }
      }
    }

    let href=OFFICIAL_URL;
    const inlineUrl=(line.match(/https?:\/\/[^)\s]+/i)||[])[0];
    if(inlineUrl && /mycert\.org\.my/i.test(inlineUrl)) href=inlineUrl;
    const item=buildItem(line,href,date);
    if(item) items.push(item);
  }

  // Last-resort multiline regex for rendered content.
  const blockRe=/(?:\[?(\d{1,2}[-\/]\d{1,2}[-\/]20\d{2})\]?\s*)?(MA-\d+\.\d+\s*:\s*MyCERT\s+(?:Advisory|Alert)[^\n]{4,300})/gi;
  let b;
  while((b=blockRe.exec(text))){
    const item=buildItem(`${b[1]||''} ${b[2]}`,OFFICIAL_URL,parseDate(b[1]));
    if(item) items.push(item);
  }

  return dedupeSort(items);
}

async function fetchText(url,{reader=false,attempts=2}={}){
  let last;
  for(let attempt=1;attempt<=attempts;attempt++){
    const ctl=new AbortController();
    const timer=setTimeout(()=>ctl.abort(), reader ? 90000 : 30000);
    try{
      console.log(`GET ${url} (attempt ${attempt}/${attempts})`);
      const headers=reader ? {
        'Accept':'text/plain,text/markdown;q=0.9,*/*;q=0.5',
        'User-Agent':'CTI-Dashboard/1.0'
      } : {
        'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/151 Safari/537.36 CTI-Dashboard/1.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language':'en-MY,en;q=0.9',
        'Cache-Control':'no-cache'
      };
      const r=await fetch(url,{signal:ctl.signal,redirect:'follow',headers});
      const body=await r.text();
      if(!r.ok) throw new Error(`HTTP ${r.status}: ${body.slice(0,180).replace(/\s+/g,' ')}`);
      if(!/MyCERT|CyberSecurity Malaysia|MA-\d+\.\d+/i.test(body)) throw new Error('Response did not look like MyCERT content');
      return body;
    }catch(e){
      last=e;
      console.warn(`Request failed: ${e.message}`);
      if(attempt<attempts) await sleep(2500*attempt);
    }finally{
      clearTimeout(timer);
    }
  }
  throw last||new Error('Fetch failed');
}

function readExisting(){
  try{return JSON.parse(fs.readFileSync(OUT,'utf8'));}catch{return null;}
}

function writePayload(advisories,metaExtra={}){
  const cutoff=Date.now()-30*86400000;
  const payload={
    meta:{
      status:'ok',
      source:'MyCERT / CyberSecurity Malaysia',
      sourceUrl:OFFICIAL_URL,
      collectedAt:nowIso(),
      lastAttemptAt:nowIso(),
      lastAttemptStatus:'ok',
      note:'MyCERT advisories. Direct collection is preferred; a reader transport is used only when the official site blocks GitHub-hosted runners.',
      ...metaExtra
    },
    stats:{
      totalLoaded:advisories.length,
      last30d:advisories.filter(a=>a.date&&new Date(`${a.date}T00:00:00Z`).getTime()>=cutoff).length,
      criticalSignals:advisories.filter(a=>a.severity==='CRITICAL SIGNAL').length,
      ransomwareSignals:advisories.filter(a=>a.type==='RANSOMWARE').length
    },
    advisories
  };
  fs.writeFileSync(OUT,JSON.stringify(payload,null,2)+'\n');
}

async function main(){
  fs.mkdirSync(path.dirname(OUT),{recursive:true});
  let error=null;

  // 1) Preferred path: official MyCERT directly.
  for(const url of DIRECT_URLS){
    try{
      const html=await fetchText(url,{reader:false,attempts:1});
      const advisories=extractFromHtml(html,url);
      if(!advisories.length) throw new Error('No advisory records parsed from direct MyCERT response');
      writePayload(advisories,{collectionMode:'direct',transport:'official-site'});
      console.log(`SUCCESS: saved ${advisories.length} MyCERT advisories directly from MyCERT.`);
      return;
    }catch(e){
      error=e;
      console.warn(`Direct MyCERT path failed: ${e.message}`);
    }
  }

  // 2) Fallback path: render the same official MyCERT page via Jina Reader.
  //    No Jina API key is required for this low-frequency basic usage.
  for(let i=0;i<READER_URLS.length;i++){
    const readerUrl=READER_URLS[i];
    try{
      console.log('Direct access is blocked; trying reader transport fallback.');
      const md=await fetchText(readerUrl,{reader:true,attempts:2});
      const advisories=extractFromMarkdown(md);
      if(!advisories.length) throw new Error('No advisory records parsed from reader response');
      writePayload(advisories,{
        collectionMode:'reader-fallback',
        transport:'Jina Reader',
        transportUrl:readerUrl,
        note:'Authoritative content: MyCERT / CyberSecurity Malaysia. Jina Reader was used only as a rendering transport because MyCERT returned a Cloudflare block to the GitHub Actions runner.'
      });
      console.log(`SUCCESS: saved ${advisories.length} MyCERT advisories via reader transport fallback.`);
      return;
    }catch(e){
      error=e;
      console.warn(`Reader fallback failed: ${e.message}`);
    }
  }

  // 3) Never wipe the last known-good dataset on an upstream/CDN failure.
  const existing=readExisting();
  if(existing?.meta?.status==='ok' && Array.isArray(existing?.advisories) && existing.advisories.length){
    existing.meta.lastAttemptAt=nowIso();
    existing.meta.lastAttemptStatus='failed';
    existing.meta.lastError=String(error?.message||'Unknown fetch error').slice(0,500);
    existing.meta.note='Refresh failed, so the last known-good MyCERT dataset was preserved.';
    fs.writeFileSync(OUT,JSON.stringify(existing,null,2)+'\n');
    console.warn('::warning::MyCERT refresh failed on all transports; preserved last successful dataset.');
    return;
  }

  // First-run resilience: write a degraded record rather than breaking the whole
  // scheduled workflow. The bundled bootstrap JSON should normally prevent this.
  const degraded={
    meta:{
      status:'degraded',
      source:'MyCERT / CyberSecurity Malaysia',
      sourceUrl:OFFICIAL_URL,
      collectedAt:null,
      lastAttemptAt:nowIso(),
      lastAttemptStatus:'failed',
      lastError:String(error?.message||'Unknown fetch error').slice(0,500),
      note:'MyCERT could not be refreshed on this run. The workflow will retry automatically on the next schedule.'
    },
    stats:{totalLoaded:0,last30d:0,criticalSignals:0,ransomwareSignals:0},
    advisories:[]
  };
  fs.writeFileSync(OUT,JSON.stringify(degraded,null,2)+'\n');
  console.warn('::warning::MyCERT could not be collected on first run; wrote degraded health state and will retry later.');
}

main().catch(e=>{console.error('MyCERT collection failed:',e);process.exit(1);});
