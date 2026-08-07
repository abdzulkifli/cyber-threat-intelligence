const fs = require('fs');
const path = require('path');

const OUT = path.join(process.cwd(), 'data', 'mycert.json');
const SOURCES = [
  'https://mycert.org.my/portal/index',
  'https://www.mycert.org.my/portal/index',
  'https://mycert.org.my/portal/advisories',
  'https://www.mycert.org.my/portal/advisories'
];

const sleep = ms => new Promise(r => setTimeout(r, ms));
function nowIso(){ return new Date().toISOString(); }
function decodeHtml(s=''){
  return s.replace(/&nbsp;/gi,' ').replace(/&amp;/gi,'&').replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'")
    .replace(/&lt;/gi,'<').replace(/&gt;/gi,'>').replace(/&#(\d+);/g,(_,n)=>String.fromCharCode(Number(n)));
}
function stripHtml(s=''){
  return decodeHtml(s.replace(/<script[\s\S]*?<\/script>/gi,' ').replace(/<style[\s\S]*?<\/style>/gi,' ').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim());
}
function normalizeUrl(href, base){
  try { return new URL(decodeHtml(href), base).href; } catch { return base; }
}
function parseDate(s){
  const m=String(s||'').match(/(\d{1,2})[-\/]([01]?\d)[-\/](20\d{2})/); if(!m)return null;
  const [_,d,mo,y]=m; return `${y}-${String(mo).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
}
function classify(title){
  const t=title.toLowerCase();
  if(t.includes('ransomware')) return 'RANSOMWARE';
  if(t.includes('phishing')||t.includes('scam')) return 'PHISHING';
  if(t.includes('malware')||t.includes('botnet')) return 'MALWARE';
  if(t.includes('alert')) return 'ALERT';
  if(t.includes('vulnerab')||t.includes('exploit')||t.includes('remote code')||t.includes('rce')) return 'VULNERABILITY';
  return 'ADVISORY';
}
function severity(title){
  const t=title.toLowerCase();
  if(t.includes('critical')||t.includes('actively exploited')||t.includes('active exploitation')||t.includes('ransomware')) return 'CRITICAL SIGNAL';
  if(t.includes('high-severity')||t.includes('high severity')||t.includes('multiple vulnerab')) return 'HIGH SIGNAL';
  return '';
}
function extractAdvisories(html, baseUrl){
  const anchors=[]; const re=/<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi; let m;
  while((m=re.exec(html))){ const text=stripHtml(m[2]); if(/\bMA-\d+\.\d+\b/i.test(text)) anchors.push({text,href:normalizeUrl(m[1],baseUrl)}); }
  const plain=stripHtml(html);
  const dateById=new Map();
  const dm=/(\d{1,2}[-\/]\d{1,2}[-\/]20\d{2})\s+(MA-\d+\.\d+)/gi; let d;
  while((d=dm.exec(plain))) dateById.set(d[2].toUpperCase(),parseDate(d[1]));
  const items=[]; const seen=new Set();
  for(const a of anchors){
    const id=(a.text.match(/MA-\d+\.\d+/i)||[])[0]; if(!id||seen.has(id.toUpperCase()))continue; seen.add(id.toUpperCase());
    let title=a.text.replace(/^\s*\[?\d{1,2}[-\/]\d{1,2}[-\/]20\d{2}\]?\s*/,'').trim();
    const date=parseDate(a.text)||dateById.get(id.toUpperCase())||null;
    const cves=[...new Set((title.match(/CVE-\d{4}-\d{4,7}/gi)||[]).map(x=>x.toUpperCase()))];
    items.push({id:id.toUpperCase(),date,title,url:a.href,type:classify(title),severity:severity(title),cves});
  }
  if(!items.length){
    const pr=/(\d{1,2}[-\/]\d{1,2}[-\/]20\d{2})\s+(MA-\d+\.\d+\s*:\s*[^\[]+?)(?=\s+\d{1,2}[-\/]\d{1,2}[-\/]20\d{2}|$)/gi; let x;
    while((x=pr.exec(plain))&&items.length<30){
      const full=x[2].trim(),id=(full.match(/MA-\d+\.\d+/i)||[])[0]; if(!id||seen.has(id.toUpperCase()))continue; seen.add(id.toUpperCase());
      const cves=[...new Set((full.match(/CVE-\d{4}-\d{4,7}/gi)||[]).map(v=>v.toUpperCase()))];
      items.push({id:id.toUpperCase(),date:parseDate(x[1]),title:full,url:baseUrl,type:classify(full),severity:severity(full),cves});
    }
  }
  items.sort((a,b)=>String(b.date||'').localeCompare(String(a.date||''))||b.id.localeCompare(a.id));
  return items.slice(0,30);
}
async function getHtml(url){
  let last;
  for(let attempt=1;attempt<=3;attempt++){
    const ctl=new AbortController(); const timer=setTimeout(()=>ctl.abort(),45000);
    try{
      console.log(`GET ${url} (attempt ${attempt}/3)`);
      const r=await fetch(url,{signal:ctl.signal,redirect:'follow',headers:{
        'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/151 Safari/537.36 CTI-Dashboard/1.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language':'en-MY,en;q=0.9',
        'Cache-Control':'no-cache'
      }});
      const text=await r.text();
      if(!r.ok) throw new Error(`HTTP ${r.status}: ${text.slice(0,160).replace(/\s+/g,' ')}`);
      if(!/MyCERT|Malaysia Computer Emergency Response Team/i.test(text)) throw new Error('Response did not look like MyCERT content');
      return text;
    }catch(e){ last=e; console.warn(`Request failed: ${e.message}`); if(attempt<3)await sleep(2500*attempt); }
    finally{ clearTimeout(timer); }
  }
  throw last||new Error('MyCERT fetch failed');
}
function readExisting(){ try{return JSON.parse(fs.readFileSync(OUT,'utf8'));}catch{return null;} }
async function main(){
  fs.mkdirSync(path.dirname(OUT),{recursive:true}); let error=null;
  for(const url of SOURCES){
    try{
      const html=await getHtml(url); const advisories=extractAdvisories(html,url);
      if(!advisories.length) throw new Error('No MyCERT advisory records could be parsed');
      const cutoff=Date.now()-30*86400000;
      const payload={
        meta:{status:'ok',source:'MyCERT / CyberSecurity Malaysia',sourceUrl:url,collectedAt:nowIso(),lastAttemptAt:nowIso(),lastAttemptStatus:'ok',note:'Public MyCERT advisories collected directly from the official MyCERT website.'},
        stats:{
          totalLoaded:advisories.length,
          last30d:advisories.filter(a=>a.date&&new Date(`${a.date}T00:00:00Z`).getTime()>=cutoff).length,
          criticalSignals:advisories.filter(a=>a.severity==='CRITICAL SIGNAL').length,
          ransomwareSignals:advisories.filter(a=>a.type==='RANSOMWARE').length
        },
        advisories
      };
      fs.writeFileSync(OUT,JSON.stringify(payload,null,2)+'\n');
      console.log(`Saved ${advisories.length} MyCERT advisories from ${url}`); return;
    }catch(e){ error=e; console.warn(`${url} failed: ${e.message}`); }
  }
  const existing=readExisting();
  if(existing?.meta?.status==='ok'){
    existing.meta.lastAttemptAt=nowIso(); existing.meta.lastAttemptStatus='failed'; existing.meta.lastError=String(error?.message||'Unknown fetch error').slice(0,500);
    fs.writeFileSync(OUT,JSON.stringify(existing,null,2)+'\n');
    console.warn('::warning::MyCERT refresh failed; preserved the last successful dataset and marked source health degraded.');
    return;
  }
  throw error||new Error('Unable to collect MyCERT advisories and no prior dataset exists.');
}
main().catch(e=>{console.error('MyCERT collection failed:',e);process.exit(1);});
