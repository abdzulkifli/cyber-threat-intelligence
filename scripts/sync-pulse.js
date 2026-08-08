#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const CONFIG_PATH = process.env.PULSE_SOURCES || path.join(ROOT, 'data', 'pulse-sources.json');
const OUT_PATH = process.env.PULSE_OUTPUT || path.join(ROOT, 'data', 'pulse.json');
const MAX_PER_SOURCE = Math.max(10, Number(process.env.PULSE_MAX_PER_SOURCE || 120));
const RETENTION_DAYS = Math.max(1, Number(process.env.PULSE_RETENTION_DAYS || 30));
const FETCH_TIMEOUT_MS = Math.max(5000, Number(process.env.PULSE_FETCH_TIMEOUT_MS || 20000));
const USER_AGENT = process.env.PULSE_USER_AGENT || 'ThreadHub-Pulse/4.0 (+https://futurelogic.my/)';
const VALIDATE_ONLY = process.argv.includes('--validate');

const STOP = new Set('a an and are as at be been by for from has have in into is it its latest new of on or over security the this to update updates vulnerability vulnerabilities with'.split(' '));
const RANSOMWARE_NAMES = ['akira','black basta','blackcat','alphv','clop','cl0p','dragonforce','hunters international','inc ransomware','lockbit','medusa','play ransomware','qilin','ransomhouse','rhysida','ransomexx','royal','scattered spider'];

function nowIso(){ return new Date().toISOString(); }
function safeDate(v){ const d = new Date(v || 0); return Number.isNaN(d.getTime()) ? '' : d.toISOString(); }
function daysAgo(v){ const t = new Date(v || 0).getTime(); return t ? Math.max(0,(Date.now()-t)/86400000) : 99999; }
function clamp(n,min,max){ return Math.max(min,Math.min(max,n)); }
function sha(v){ return crypto.createHash('sha256').update(String(v)).digest('hex').slice(0,20); }
function decodeXml(s=''){
  return String(s)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,'$1')
    .replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"')
    .replace(/&#39;|&apos;/g,"'").replace(/&amp;/g,'&')
    .replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi,(_,n)=>String.fromCodePoint(parseInt(n,16)));
}
function stripHtml(s=''){ return decodeXml(s).replace(/<script[\s\S]*?<\/script>/gi,' ').replace(/<style[\s\S]*?<\/style>/gi,' ').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim(); }
function tag(block,name){ const m = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${name}>`,'i')); return m ? stripHtml(m[1]) : ''; }
function atomLink(block){
  const links = [...block.matchAll(/<link\b([^>]*)>/gi)];
  for(const m of links){
    const attrs=m[1]||'',href=(attrs.match(/\bhref=["']([^"']+)["']/i)||[])[1],rel=(attrs.match(/\brel=["']([^"']+)["']/i)||[])[1]||'alternate';
    if(href && (rel==='alternate'||!rel)) return decodeXml(href);
  }
  return '';
}
function parseFeed(xml,source){
  const isAtom=/<feed\b/i.test(xml)&&/<entry\b/i.test(xml);
  const blocks=isAtom?[...xml.matchAll(/<entry\b[^>]*>([\s\S]*?)<\/entry>/gi)].map(m=>m[1]):[...xml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)].map(m=>m[1]);
  return blocks.slice(0,MAX_PER_SOURCE).map(block=>{
    const title=tag(block,'title');
    const url=isAtom?atomLink(block):(tag(block,'link')||tag(block,'guid'));
    const published=tag(block,isAtom?'published':'pubDate')||tag(block,'updated')||tag(block,'dc:date')||tag(block,'date');
    const summary=tag(block,'description')||tag(block,'summary')||tag(block,'content')||tag(block,'content:encoded');
    const id=tag(block,'guid')||tag(block,'id')||url||`${title}:${published}`;
    return normalizeItem({title,url,published,summary,id},source);
  }).filter(x=>x.title && x.url && /^https?:\/\//i.test(x.url));
}

function htmlDecodeText(s=''){ return stripHtml(String(s).replace(/\\u0026/g,'&')); }
function absoluteUrl(href,base){ try{return new URL(decodeXml(href),base).href}catch{return''} }
function nearbyDate(html,index){
  const chunk=html.slice(Math.max(0,index-700),Math.min(html.length,index+1300));
  const iso=(chunk.match(/\b(20\d{2})[-\/](\d{1,2})[-\/](\d{1,2})\b/)||[]);
  if(iso[0]) return safeDate(`${iso[1]}-${String(iso[2]).padStart(2,'0')}-${String(iso[3]).padStart(2,'0')}T12:00:00Z`);
  const named=(chunk.match(/\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),?\s+(20\d{2})\b/i)||[]);
  if(named[0]) return safeDate(named[0]);
  return '';
}
function parseHtmlListing(html,source,matcher){
  const out=[],seen=new Set(),re=new RegExp('<a\\b[^>]*href=["\\\']([^"\\\']+)["\\\'][^>]*>([\\s\\S]*?)<\\/a>','gi');
  let m;
  while((m=re.exec(html)) && out.length<MAX_PER_SOURCE){
    const url=absoluteUrl(m[1],source.url),title=htmlDecodeText(m[2]);
    if(!url||!title||title.length<8||!matcher(url,title)) continue;
    const clean=url.replace(/[?#].*$/,''); if(seen.has(clean)) continue; seen.add(clean);
    const idx=m.index,context=stripHtml(html.slice(Math.max(0,idx-350),Math.min(html.length,idx+1600))).slice(0,1100);
    const published=nearbyDate(html,idx)||nowIso();
    out.push(normalizeItem({title,url:clean,published,summary:context,id:clean},source));
  }
  return out;
}
function parseCisaKevJson(text,source){
  const data=JSON.parse(text),rows=Array.isArray(data)?data:(data.vulnerabilities||[]);
  return rows.slice().sort((a,b)=>String(b.dateAdded||'').localeCompare(String(a.dateAdded||''))).slice(0,MAX_PER_SOURCE).map(v=>{
    const title=`${v.cveID||v.cve||'CVE'} · ${v.vendorProject||v.vendor||''} ${v.product||''}`.trim();
    const summary=[v.vulnerabilityName,v.shortDescription,v.requiredAction,v.knownRansomwareCampaignUse&&`Known ransomware use: ${v.knownRansomwareCampaignUse}`].filter(Boolean).join(' · ');
    const cve=v.cveID||v.cve||'';
    const url=cve?`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(cve)}`:(source.homepage||source.url);
    return normalizeItem({title,url,published:v.dateAdded||nowIso(),summary,id:cve||title},source);
  }).filter(x=>daysAgo(x.published)<=RETENTION_DAYS);
}
function parseByAdapter(text,source){
  if(source.type==='cisa-kev-json') return parseCisaKevJson(text,source);
  if(source.type==='cisa-advisories-html') return parseHtmlListing(text,source,(u)=>/\/news-events\/cybersecurity-advisories\/[^/?#]+/i.test(u));
  if(source.type==='cisa-ics-html') return parseHtmlListing(text,source,(u)=>/\/news-events\/ics-advisories\/[^/?#]+/i.test(u));
  if(source.type==='cert-eu-html'){
    const path=source.matchPath||'/publications/';
    return parseHtmlListing(text,source,(u)=>u.includes('cert.europa.eu')&&u.includes(path)&&!new RegExp(`${path.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}20\\d{2}/?$`).test(u));
  }
  return parseFeed(text,source);
}

function extractCves(text){ return [...new Set((String(text).match(/CVE-\d{4}-\d{4,7}/gi)||[]).map(x=>x.toUpperCase()))]; }
function extractRansomware(text){ const lower=String(text).toLowerCase(); return RANSOMWARE_NAMES.filter(n=>lower.includes(n)); }
function classify(text){
  const t=String(text).toLowerCase();
  if(/ransomware|double extortion|data extortion|encryptor/.test(t)) return 'ransomware';
  if(/data breach|data leak|breached|stolen data|records exposed|records leaked/.test(t)) return 'breach';
  if(/malware|infostealer|info-stealer|trojan|botnet|backdoor|rootkit|worm|loader/.test(t)) return 'malware';
  if(/threat actor|apt\d*\b|unc\d+\b|campaign|nation.state|espionage/.test(t)) return 'threat-actor';
  if(/cve-\d{4}-\d+|zero.day|zero day|vulnerabilit|remote code execution|privilege escalation|security bulletin|security advisory/.test(t)) return 'vulnerability';
  if(/phishing|credential theft|business email compromise|bec\b/.test(t)) return 'phishing';
  return 'advisory';
}
function severityHints(text){
  const t=String(text).toLowerCase(); let s=0;
  if(/critical/.test(t)) s=Math.max(s,10);
  else if(/high severity|important/.test(t)) s=Math.max(s,7);
  if(/zero.day|zero day|actively exploited|exploited in the wild|active exploitation/.test(t)) s=10;
  if(/ransomware/.test(t)) s=Math.max(s,8);
  if(/data breach|data leak/.test(t)) s=Math.max(s,7);
  return s;
}
function normalizeTitle(title){
  return String(title).toLowerCase().replace(/cve-\d{4}-\d{4,7}/gi,' ').replace(/[^a-z0-9]+/g,' ').split(/\s+/).filter(w=>w.length>2&&!STOP.has(w)).slice(0,12).join(' ');
}
function itemTokens(item){ return new Set(normalizeTitle(item.title).split(' ').filter(Boolean)); }
function jaccard(a,b){ let inter=0; for(const x of a) if(b.has(x)) inter++; const union=new Set([...a,...b]).size; return union?inter/union:0; }
function normalizeItem(raw,source){
  const text=`${raw.title||''} ${raw.summary||''}`.trim();
  const cves=extractCves(text),ransomware=extractRansomware(text),category=classify(text),published=safeDate(raw.published)||nowIso();
  return {
    id:`${source.id}:${sha(raw.id||raw.url||raw.title)}`,
    title:stripHtml(raw.title), summary:stripHtml(raw.summary).slice(0,900), url:raw.url,
    published, collectedAt:nowIso(), sourceId:source.id, sourceName:source.name,
    sourceType:source.sourceType||'research', sourceClass:source.sourceClass||source.sourceType||'OSINT', credibility:clamp(Number(source.credibility||0.7),0,1),
    category, entities:{cves,ransomwareGroups:ransomware}, severityHint:severityHints(text)
  };
}
function clusterItems(items){
  const clusters=[];
  const ordered=items.slice().sort((a,b)=>new Date(b.published)-new Date(a.published));
  for(const item of ordered){
    const cves=item.entities.cves||[],rw=item.entities.ransomwareGroups||[];
    const strongKey=cves[0]?`cve:${cves[0]}`:(rw[0]?`rw:${rw[0]}`:'');
    let target=strongKey?clusters.find(c=>c.key===strongKey && Math.abs(new Date(c.latest)-new Date(item.published))<=3*86400000):null;
    if(!target){
      const tokens=itemTokens(item);
      target=clusters.find(c=>c.category===item.category && Math.abs(new Date(c.latest)-new Date(item.published))<=4*86400000 && jaccard(c.tokens,tokens)>=0.42);
    }
    if(!target){
      target={key:strongKey||`topic:${sha(normalizeTitle(item.title))}`,category:item.category,title:item.title,tokens:itemTokens(item),items:[],firstSeen:item.published,latest:item.published};
      clusters.push(target);
    }
    target.items.push(item);
    if(new Date(item.published)<new Date(target.firstSeen)) target.firstSeen=item.published;
    if(new Date(item.published)>new Date(target.latest)){ target.latest=item.published; target.title=item.title; }
  }
  return clusters;
}
function windowCount(items,minHours,maxHours){
  return items.filter(x=>{const h=(Date.now()-new Date(x.published).getTime())/3600000;return h>=minHours&&h<maxHours}).length;
}
function growthPct(cur,prev){
  if(prev>0)return clamp(Math.round(((cur-prev)/prev)*100),-100,9999);
  if(cur<=0)return 0;
  return clamp(cur===1?50:cur===2?100:cur===3?200:cur*100,-100,9999);
}
function sourceMix(items){
  const mix={};
  for(const x of items){const k=x.sourceClass||x.sourceType||'OSINT';mix[k]=(mix[k]||0)+1}
  return mix;
}
function topicFromCluster(c,previousTopic=null){
  const items=c.items.slice().sort((a,b)=>new Date(b.published)-new Date(a.published));
  const sourceIds=[...new Set(items.map(x=>x.sourceId))],mentions=items.length;
  const h1=windowCount(items,0,1),p1=windowCount(items,1,2),h6=windowCount(items,0,6),p6=windowCount(items,6,12),h24=windowCount(items,0,24),p24=windowCount(items,24,48);
  const v1=growthPct(h1,p1),v6=growthPct(h6,p6),v24=growthPct(h24,p24);
  const velocity=Math.max(v1,v6,v24);
  const credibilityAvg=items.reduce((s,x)=>s+x.credibility,0)/Math.max(1,items.length);
  const classes=[...new Set(items.map(x=>x.sourceClass).filter(Boolean))],types=[...new Set(items.map(x=>x.sourceType).filter(Boolean))];
  const authoritative=items.some(x=>x.sourceType==='official'||x.sourceType==='vendor');
  const researchConfirmed=items.some(x=>x.sourceType==='research');
  const newsConfirmed=items.some(x=>x.sourceType==='news');
  const crossSourceConfirmed=sourceIds.length>=2 && (classes.length>=2 || types.length>=2);
  const verified=authoritative || (researchConfirmed && sourceIds.length>=2) || (sourceIds.length>=3 && classes.length>=2);
  const volumeScore=clamp(Math.round(Math.log2(mentions+1)*6),0,20);
  const velocityScore=clamp(Math.round(velocity<=0?0:Math.log2((velocity/100)+1)*9),0,20);
  const diversityScore=clamp(sourceIds.length*4 + Math.max(0,classes.length-1)*2,0,15);
  const credibilityScore=clamp(Math.round(credibilityAvg*15),0,15);
  const severityScore=clamp(Math.max(...items.map(x=>x.severityHint),0),0,10);
  const exploitScore=items.some(x=>/zero.day|zero day|actively exploited|exploited in the wild|active exploitation|known exploited/i.test(`${x.title} ${x.summary}`))?10:0;
  const recencyScore=daysAgo(c.latest)<=0.25?5:daysAgo(c.latest)<=1?4:daysAgo(c.latest)<=3?3:daysAgo(c.latest)<=7?2:1;
  const crossSourceScore=crossSourceConfirmed?5:sourceIds.length>=2?3:0;
  const score=clamp(volumeScore+velocityScore+diversityScore+credibilityScore+severityScore+exploitScore+recencyScore+crossSourceScore,0,100);
  const cves=[...new Set(items.flatMap(x=>x.entities.cves))],rw=[...new Set(items.flatMap(x=>x.entities.ransomwareGroups))];
  const emerging=(daysAgo(c.latest)<=1 && sourceIds.length>=2 && (v6>=100||v1>=100)) || (daysAgo(c.latest)<=0.5 && sourceIds.length>=3 && h24>=3);
  const momentum=emerging&&velocity>=200?'surging':velocity>=200?'surging':velocity>=50?'rising':h24?'active':daysAgo(c.latest)<=7?'active':'cooling';
  const prevMentions=Number(previousTopic?.mentions||0),runDelta=mentions-prevMentions;
  return {
    id:c.key, title:c.title, category:c.category, score, momentum, mentions, uniqueSources:sourceIds.length,
    velocityPct:velocity, firstSeen:c.firstSeen, latest:c.latest, emerging, verified, authoritativeConfirmed:authoritative,
    crossSourceConfirmed, runDeltaMentions:runDelta,
    windows:{h1,p1,h6,p6,h24,p24,velocity1hPct:v1,velocity6hPct:v6,velocity24hPct:v24},
    sourceMix:sourceMix(items), sourceClasses:classes,
    summary:items[0]?.summary||'', entities:{cves,ransomwareGroups:rw},
    primaryUrl:items[0]?.url||'', sourceLabel:items[0]?.sourceName||'',
    evidence:items.slice(0,30).map(x=>({label:x.sourceName,title:x.title,url:x.url,time:x.published,sourceType:x.sourceType,sourceClass:x.sourceClass,credibility:x.credibility})),
    scoreBreakdown:{volume:volumeScore,velocity:velocityScore,diversity:diversityScore,credibility:credibilityScore,severity:severityScore,exploitation:exploitScore,recency:recencyScore,crossSource:crossSourceScore}
  };
}
async function fetchText(url){
  const ctrl=new AbortController(); const timer=setTimeout(()=>ctrl.abort(),FETCH_TIMEOUT_MS);
  try{
    const r=await fetch(url,{headers:{'user-agent':USER_AGENT,'accept':'application/rss+xml, application/atom+xml, application/xml, text/xml, */*'},signal:ctrl.signal,redirect:'follow'});
    if(!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.text();
  } finally { clearTimeout(timer); }
}
function loadConfig(){
  const cfg=JSON.parse(fs.readFileSync(CONFIG_PATH,'utf8'));
  if(!Array.isArray(cfg.sources)) throw new Error('pulse-sources.json must contain a sources array');
  for(const s of cfg.sources){ if(!s.id||!s.name||!s.url) throw new Error(`Invalid source entry: ${JSON.stringify(s)}`); new URL(s.url); }
  return cfg;
}
async function main(){
  const cfg=loadConfig();
  if(VALIDATE_ONLY){ console.log(`Validated ${cfg.sources.length} Pulse sources.`); return; }
  let previous={topics:[]};
  try{ if(fs.existsSync(OUT_PATH)) previous=JSON.parse(fs.readFileSync(OUT_PATH,'utf8')); }catch{}
  const previousById=new Map((previous.topics||[]).map(t=>[t.id,t]));
  const statuses=[],all=[];
  for(const source of cfg.sources.filter(s=>s.enabled!==false)){
    const started=Date.now();
    try{
      console.log(`Pulse: fetching ${source.name} -> ${source.url}`);
      const payload=await fetchText(source.url),items=parseByAdapter(payload,source).filter(x=>daysAgo(x.published)<=RETENTION_DAYS);
      all.push(...items);
      statuses.push({id:source.id,name:source.name,status:'ok',items:items.length,url:source.homepage||source.url,feedUrl:source.url,sourceType:source.sourceType||'research',sourceClass:source.sourceClass||source.sourceType||'OSINT',credibility:source.credibility??0.7,collectorType:source.type||'rss',collectedAt:nowIso(),durationMs:Date.now()-started,lastSuccessAt:nowIso(),error:''});
      console.log(`Pulse: ${source.name}: ${items.length} retained items`);
    }catch(err){
      statuses.push({id:source.id,name:source.name,status:'failed',items:0,url:source.homepage||source.url,feedUrl:source.url,sourceType:source.sourceType||'research',sourceClass:source.sourceClass||source.sourceType||'OSINT',credibility:source.credibility??0.7,collectorType:source.type||'rss',collectedAt:nowIso(),durationMs:Date.now()-started,lastSuccessAt:'',error:String(err.message||err)});
      console.error(`Pulse: ${source.name} failed: ${err.message||err}`);
    }
  }
  const seen=new Map(); for(const x of all){ const k=x.url.replace(/[?#].*$/,''); if(!seen.has(k)) seen.set(k,x); }
  const items=[...seen.values()].sort((a,b)=>new Date(b.published)-new Date(a.published));
  const topics=clusterItems(items).map(c=>topicFromCluster(c,previousById.get(c.key))).sort((a,b)=>b.score-a.score||new Date(b.latest)-new Date(a.latest));
  const ok=statuses.filter(x=>x.status==='ok').length;
  const classes=[...new Set(statuses.map(x=>x.sourceClass).filter(Boolean))];
  const failed=statuses.length-ok;
  const newsHealthy=statuses.filter(x=>x.sourceClass==='Cyber News'&&x.status==='ok').length;
  const emergingCount=topics.filter(t=>t.emerging).length,verifiedCount=topics.filter(t=>t.verified).length,crossConfirmed=topics.filter(t=>t.crossSourceConfirmed).length;
  const out={
    meta:{status:ok?'ok':'failed',schemaVersion:3,collectedAt:nowIso(),collector:'ThreadHub Internet Signal Collector V4 · Wave 2',retentionDays:RETENTION_DAYS,sourcesConfigured:statuses.length,sourcesHealthy:ok,sourcesFailed:failed,newsSourcesHealthy:newsHealthy,sourceClasses:classes.length,sourceClassNames:classes,items:items.length,topics:topics.length,emergingTopics:emergingCount,verifiedTopics:verifiedCount,crossSourceConfirmedTopics:crossConfirmed},
    sources:statuses, topics, items:items.slice(0,1000)
  };
  fs.writeFileSync(OUT_PATH,JSON.stringify(out,null,2)+'\n');
  console.log(`Pulse: wrote ${topics.length} topics / ${items.length} items from ${ok}/${statuses.length} healthy sources (${emergingCount} emerging, ${verifiedCount} verified) to ${path.relative(ROOT,OUT_PATH)}`);
  if(!ok) process.exitCode=1;
}

main().catch(err=>{ console.error(err); process.exitCode=1; });
