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
const USER_AGENT = process.env.PULSE_USER_AGENT || 'ThreadHub-Pulse/1.0 (+https://futurelogic.my/)';
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
    const published=tag(block,isAtom?'published':'pubDate')||tag(block,'updated')||tag(block,'date');
    const summary=tag(block,'description')||tag(block,'summary')||tag(block,'content')||tag(block,'content:encoded');
    const id=tag(block,'guid')||tag(block,'id')||url||`${title}:${published}`;
    return normalizeItem({title,url,published,summary,id},source);
  }).filter(x=>x.title && x.url && /^https?:\/\//i.test(x.url));
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
    sourceType:source.sourceType||'research', credibility:clamp(Number(source.credibility||0.7),0,1),
    category, entities:{cves,ransomwareGroups:ransomware}, severityHint:severityHints(text)
  };
}
function clusterItems(items){
  const clusters=[];
  const ordered=items.slice().sort((a,b)=>new Date(b.published)-new Date(a.published));
  for(const item of ordered){
    const cve=item.entities.cves[0];
    let target=cve?clusters.find(c=>c.key===`cve:${cve}`):null;
    if(!target){
      const tokens=itemTokens(item);
      target=clusters.find(c=>c.category===item.category && Math.abs(new Date(c.latest)-new Date(item.published))<=7*86400000 && jaccard(c.tokens,tokens)>=0.58);
    }
    if(!target){
      target={key:cve?`cve:${cve}`:`topic:${sha(normalizeTitle(item.title))}`,category:item.category,title:item.title,tokens:itemTokens(item),items:[],firstSeen:item.published,latest:item.published};
      clusters.push(target);
    }
    target.items.push(item);
    if(new Date(item.published)<new Date(target.firstSeen)) target.firstSeen=item.published;
    if(new Date(item.published)>new Date(target.latest)){ target.latest=item.published; target.title=item.title; }
  }
  return clusters;
}
function topicFromCluster(c){
  const items=c.items.slice().sort((a,b)=>new Date(b.published)-new Date(a.published));
  const sources=[...new Set(items.map(x=>x.sourceId))],mentions=items.length;
  const last24=items.filter(x=>daysAgo(x.published)<=1).length,prev24=items.filter(x=>{const d=daysAgo(x.published);return d>1&&d<=2}).length;
  const ratio=prev24?last24/prev24:(last24?1+last24:1),velocity=clamp(Math.round((ratio-1)*100),-100,9999);
  const credibilityAvg=items.reduce((s,x)=>s+x.credibility,0)/Math.max(1,items.length);
  const volumeScore=clamp(Math.round(Math.log2(mentions+1)*6),0,20);
  const velocityScore=clamp(Math.round((ratio<=1?0:Math.log2(ratio+1)*7)),0,20);
  const diversityScore=clamp(sources.length*5,0,15);
  const credibilityScore=clamp(Math.round(credibilityAvg*15),0,15);
  const severityScore=clamp(Math.max(...items.map(x=>x.severityHint),0),0,10);
  const exploitScore=items.some(x=>/zero.day|zero day|actively exploited|exploited in the wild|active exploitation/i.test(`${x.title} ${x.summary}`))?10:0;
  const recencyScore=daysAgo(c.latest)<=1?10:daysAgo(c.latest)<=3?8:daysAgo(c.latest)<=7?6:daysAgo(c.latest)<=14?3:1;
  const score=clamp(volumeScore+velocityScore+diversityScore+credibilityScore+severityScore+exploitScore+recencyScore,0,100);
  const cves=[...new Set(items.flatMap(x=>x.entities.cves))],rw=[...new Set(items.flatMap(x=>x.entities.ransomwareGroups))];
  const momentum=velocity>=200?'surging':velocity>=50?'rising':last24?'active':daysAgo(c.latest)<=7?'active':'cooling';
  return {
    id:c.key, title:c.title, category:c.category, score, momentum, mentions, uniqueSources:sources.length,
    velocityPct:velocity, firstSeen:c.firstSeen, latest:c.latest,
    summary:items[0]?.summary||'', entities:{cves,ransomwareGroups:rw},
    primaryUrl:items[0]?.url||'', sourceLabel:items[0]?.sourceName||'',
    evidence:items.slice(0,20).map(x=>({label:x.sourceName,title:x.title,url:x.url,time:x.published,sourceType:x.sourceType,credibility:x.credibility})),
    scoreBreakdown:{volume:volumeScore,velocity:velocityScore,diversity:diversityScore,credibility:credibilityScore,severity:severityScore,exploitation:exploitScore,recency:recencyScore}
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
  const statuses=[],all=[];
  for(const source of cfg.sources.filter(s=>s.enabled!==false)){
    const started=Date.now();
    try{
      console.log(`Pulse: fetching ${source.name} -> ${source.url}`);
      const xml=await fetchText(source.url),items=parseFeed(xml,source).filter(x=>daysAgo(x.published)<=RETENTION_DAYS);
      all.push(...items);
      statuses.push({id:source.id,name:source.name,status:'ok',items:items.length,url:source.homepage||source.url,collectedAt:nowIso(),durationMs:Date.now()-started});
      console.log(`Pulse: ${source.name}: ${items.length} retained items`);
    }catch(err){
      statuses.push({id:source.id,name:source.name,status:'failed',items:0,url:source.homepage||source.url,collectedAt:nowIso(),durationMs:Date.now()-started,error:String(err.message||err)});
      console.error(`Pulse: ${source.name} failed: ${err.message||err}`);
    }
  }
  const seen=new Map(); for(const x of all){ const k=x.url.replace(/[?#].*$/,''); if(!seen.has(k)) seen.set(k,x); }
  const items=[...seen.values()].sort((a,b)=>new Date(b.published)-new Date(a.published));
  const topics=clusterItems(items).map(topicFromCluster).sort((a,b)=>b.score-a.score||new Date(b.latest)-new Date(a.latest));
  const ok=statuses.filter(x=>x.status==='ok').length;
  const out={
    meta:{status:ok?'ok':'failed',schemaVersion:1,collectedAt:nowIso(),collector:'ThreadHub Internet Signal Collector V1',retentionDays:RETENTION_DAYS,sourcesConfigured:statuses.length,sourcesHealthy:ok,items:items.length,topics:topics.length},
    sources:statuses, topics, items:items.slice(0,500)
  };
  fs.writeFileSync(OUT_PATH,JSON.stringify(out,null,2)+'\n');
  console.log(`Pulse: wrote ${topics.length} topics / ${items.length} items from ${ok}/${statuses.length} healthy sources to ${path.relative(ROOT,OUT_PATH)}`);
  if(!ok) process.exitCode=1;
}

main().catch(err=>{ console.error(err); process.exitCode=1; });
