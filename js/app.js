let KEV=null,NVD=null,EPSS=null,RW=null,MYCERT=null;
let NVD_BY_ID=new Map(),EPSS_BY_ID=new Map();
let PAGE=1; const PAGE_SIZE=50;
let FEED_FILTER='all',FEED_LIMIT=18,KNOWN_FEED_IDS=null;
const $=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const fmt=n=>Number(n||0).toLocaleString();
function fmtDateTime(v){if(!v)return'Not collected';const d=new Date(v);return Number.isNaN(d.getTime())?'—':d.toLocaleString();}
function ageDays(s){if(!s)return Infinity;return(Date.now()-new Date(`${s}T00:00:00Z`).getTime())/86400000;}
function relTime(v){if(!v)return'Unknown time';const t=new Date(v).getTime();if(!Number.isFinite(t))return'Unknown time';const m=Math.max(0,Math.floor((Date.now()-t)/60000));if(m<60)return`${m}m ago`;const h=Math.floor(m/60);if(h<48)return`${h}h ago`;return`${Math.floor(h/24)}d ago`;}
function priorityLabel(s){return s>=75?'CRITICAL':s>=55?'HIGH':s>=35?'MEDIUM':'LOW';}
function ctiPriority(v){const sev=String(v.nvd?.cvss?.severity||'UNKNOWN').toUpperCase();let s=({CRITICAL:30,HIGH:24,MEDIUM:15,LOW:8,UNKNOWN:5})[sev]??5;const p=Number(v.epss?.epss||0);s+=p>=.7?35:p>=.5?32:p>=.2?28:p>=.1?24:p>=.05?20:p>=.01?14:6;if(v.ransomware)s+=25;const a=ageDays(v.dateAdded);s+=a<=7?10:a<=30?6:a<=90?3:0;s=Math.min(100,s);return{score:s,label:priorityLabel(s)};}
function buildUnified(){return(KEV?.vulnerabilities||[]).map(v=>{const x={...v,nvd:NVD_BY_ID.get(v.id)||null,epss:EPSS_BY_ID.get(v.id)||null};x.priority=ctiPriority(x);return x;});}
function sourceReady(x){return x?.meta?.status==='ok';}
function setHealth(id,state){const el=$(id);if(!el)return;const cls=state===true||state==='ok'?'ok':state==='warn'?'warn':'';el.className=`health-dot ${cls}`;}
function renderHeader(){const states=[sourceReady(KEV),sourceReady(NVD),sourceReady(EPSS),sourceReady(RW),sourceReady(MYCERT)];const n=states.filter(Boolean).length;const myDegraded=sourceReady(MYCERT)&&MYCERT?.meta?.lastAttemptStatus==='failed';const liveCount=myDegraded?Math.max(0,n-1):n;$('feedStatus').textContent=n===5&&!myDegraded?'5 SOURCES LIVE':myDegraded?`${liveCount} LIVE · 1 DEGRADED`:`${n} SOURCE${n===1?'':'S'} LIVE`;$('feedStatus').title=myDegraded?'Degraded source: MyCERT Malaysia':'';$('liveDot').className=`dot ${n===5&&!myDegraded?'':'amber-dot'}`;setHealth('cisaHealthDot',states[0]);setHealth('nvdHealthDot',states[1]);setHealth('epssHealthDot',states[2]);setHealth('rwHealthDot',states[3]);setHealth('mycertHealthDot',myDegraded?'warn':states[4]);$('cisaCollectedAt').textContent=fmtDateTime(KEV?.meta?.collectedAt);$('nvdCollectedAt').textContent=fmtDateTime(NVD?.meta?.collectedAt);$('epssCollectedAt').textContent=fmtDateTime(EPSS?.meta?.collectedAt);$('rwCollectedAt').textContent=fmtDateTime(RW?.meta?.collectedAt);$('mycertCollectedAt').textContent=sourceReady(MYCERT)?fmtDateTime(MYCERT?.meta?.collectedAt):'Not collected';}
function renderTopMetrics(){const unified=buildUnified();const criticalPriority=unified.filter(x=>x.priority.label==='CRITICAL').length;$('total').textContent=fmt(KEV?.stats?.total);$('ransomware').textContent=fmt(KEV?.stats?.ransomwareRelated);$('critical').textContent=fmt(NVD?.stats?.critical);$('high').textContent=fmt(NVD?.stats?.high);$('priorityCriticalTop').textContent=fmt(criticalPriority);$('epss50Top').textContent=fmt(EPSS?.stats?.epssGe50);$('rwTotalVictims').textContent=sourceReady(RW)?fmt(RW.stats.totalVictims):'—';$('rwActiveGroups').textContent=sourceReady(RW)?fmt(RW.stats.activeGroups):'—';$('rw24h').textContent=sourceReady(RW)?fmt(RW.stats.claims24h):'—';$('rwCountries').textContent=sourceReady(RW)?fmt(RW.stats.countriesRecent):'—';const epssHigh=Number(EPSS?.stats?.epssGe50||0);const rw24=Number(RW?.stats?.claims24h||0);const score=Math.min(100,Math.round((criticalPriority/Math.max(unified.length,1))*1500 + Math.min(35,epssHigh/8) + Math.min(30,rw24*2)));$('pulseScore').textContent=score||'—';const label=score>=75?'HEIGHTENED':score>=50?'ELEVATED':score>=25?'GUARDED':'NORMAL';$('pulseLabel').textContent=`${label} external threat posture`;$('pulseStatus').textContent=label;$('pulseStatus').dataset.level=label.toLowerCase();$('pulseNarrative').textContent=sourceReady(RW)?`${fmt(criticalPriority)} KEVs currently rank Critical by CTI priority, while ${fmt(rw24)} ransomware claims in the latest feed were discovered within 24 hours.`:'Vulnerability intelligence is live. Ransomware activity enrichment is waiting for its first collection.';}
function renderEpss(){if(!sourceReady(EPSS)){['epssCoverage','epss10','epss99'].forEach(id=>$(id).textContent='—');return;}$('epssCoverage').textContent=`${Number(EPSS.stats.coveragePercent||0).toFixed(1)}%`;$('epssCoverageHint').textContent=`${fmt(EPSS.stats.matched)} KEVs scored`;$('epss10').textContent=fmt(EPSS.stats.epssGe10);$('epss99').textContent=fmt(EPSS.stats.percentileGe99);$('epssScoreDate').textContent=`Score date ${EPSS.meta.scoreDate||'current'}`;}
function renderSeverity(){if(!sourceReady(NVD)){return;}const s=NVD.stats;$('sevCritical').textContent=fmt(s.critical);$('sevHigh').textContent=fmt(s.high);$('sevMedium').textContent=fmt(s.medium);$('sevLow').textContent=fmt(s.low);$('severityCoverage').textContent=`${Number(s.coveragePercent||0).toFixed(1)}% CVSS coverage`;const total=Math.max(1,Number(s.total||0));$('severityStack').innerHTML=[['critical',s.critical],['high',s.high],['medium',s.medium],['low',s.low],['unknown',s.unknown]].map(([k,n])=>`<span class="stack-${k}" style="width:${Number(n||0)/total*100}%" title="${k}: ${fmt(n)}"></span>`).join('');}
function renderVendors(){const list=KEV?.stats?.topVendors||[];const max=Math.max(...list.map(x=>x.count),1);$('vendors').innerHTML=list.map(v=>`<div class="vendor-row"><div class="vendor-name"><strong>${esc(v.name)}</strong><span>${fmt(v.count)}</span></div><div class="vendor-bar"><div class="vendor-fill" style="width:${Math.max(4,v.count/max*100)}%"></div></div></div>`).join('');$('vendorCount').textContent=`${list.length} vendors shown`;}
function renderRansomware(){const ready=sourceReady(RW);['rwRecentClaims','rw24hCard','rwTrackedGroups','rwCountriesCard','rwSectors'].forEach(id=>$(id).textContent='—');if(!ready){$('rwTopGroups').innerHTML='<div class="empty-state">Run “Update Ransomware Intelligence” in GitHub Actions.</div>';$('rwCountriesList').innerHTML=$('rwSectorsList').innerHTML='';$('rwLiveFeed').innerHTML='<div class="empty-state">Waiting for first ransomware collection…</div>';return;}$('rwRecentClaims').textContent=fmt(RW.stats.recentClaims);$('rw24hCard').textContent=fmt(RW.stats.claims24h);$('rwTrackedGroups').textContent=fmt(RW.stats.trackedGroups);$('rwCountriesCard').textContent=fmt(RW.stats.countriesRecent);$('rwSectors').textContent=fmt(RW.stats.sectorsRecent);$('rwGroupSample').textContent=`${fmt(RW.stats.recentClaims)} latest claims`;renderRanking('rwTopGroups',RW.topGroups||[],8,true);renderRanking('rwCountriesList',RW.topCountries||[],7,false);renderRanking('rwSectorsList',RW.topSectors||[],7,false);renderActivity(RW.dailyActivity||[]);$('rwLiveFeed').innerHTML=(RW.victims||[]).slice(0,12).map(v=>`<div class="claim-item"><div class="claim-marker"></div><div class="claim-copy"><div><strong>${esc(v.victim||'Unknown')}</strong><span class="group-tag">${esc(v.group||'Unknown')}</span></div><small>${esc(v.country||'Unknown')} · ${esc(v.sector||'Unspecified')} · ${relTime(v.discovered)}</small></div></div>`).join('')||'<div class="empty-state">No recent claims returned.</div>';}
const ASEAN_MEMBERS=[
  {name:'Malaysia',code:'MY',flag:'🇲🇾',aliases:['MALAYSIA','MY','MYS']},
  {name:'Singapore',code:'SG',flag:'🇸🇬',aliases:['SINGAPORE','SG','SGP']},
  {name:'Indonesia',code:'ID',flag:'🇮🇩',aliases:['INDONESIA','ID','IDN']},
  {name:'Thailand',code:'TH',flag:'🇹🇭',aliases:['THAILAND','TH','THA']},
  {name:'Philippines',code:'PH',flag:'🇵🇭',aliases:['PHILIPPINES','PHILIPPINE','PH','PHL']},
  {name:'Viet Nam',code:'VN',flag:'🇻🇳',aliases:['VIET NAM','VIETNAM','VN','VNM']},
  {name:'Brunei Darussalam',code:'BN',flag:'🇧🇳',aliases:['BRUNEI','BRUNEI DARUSSALAM','BN','BRN']},
  {name:'Cambodia',code:'KH',flag:'🇰🇭',aliases:['CAMBODIA','KH','KHM']},
  {name:'Lao PDR',code:'LA',flag:'🇱🇦',aliases:['LAOS','LAO','LAO PDR','LAO PEOPLE S DEMOCRATIC REPUBLIC','LA','LAO']},
  {name:'Myanmar',code:'MM',flag:'🇲🇲',aliases:['MYANMAR','BURMA','MM','MMR']},
  {name:'Timor-Leste',code:'TL',flag:'🇹🇱',aliases:['TIMOR-LESTE','TIMOR LESTE','EAST TIMOR','TL','TLS']}
];
function cleanCountry(v){return String(v||'').trim().toUpperCase().replace(/[^A-Z0-9]+/g,' ').trim();}
function aseanMember(raw){const x=cleanCountry(raw);if(!x)return null;return ASEAN_MEMBERS.find(m=>m.aliases.some(a=>cleanCountry(a)===x))||null;}
function withinDays(v,days){if(!v)return false;const t=new Date(v).getTime();return Number.isFinite(t)&&(Date.now()-t)<=days*86400000&&(Date.now()-t)>=-86400000;}
function countBy(items,keyFn){const m=new Map();for(const x of items){const k=keyFn(x);if(!k)continue;m.set(k,(m.get(k)||0)+1);}return [...m.entries()].map(([name,count])=>({name,count})).sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name));}
function safeMycertUrl(v){try{const u=new URL(v,'https://mycert.org.my');return /(^|\.)mycert\.org\.my$/i.test(u.hostname)?u.href:'#';}catch{return '#';}}
function renderRegional(){
  const victims=sourceReady(RW)?(RW.victims||[]):[];
  const regional=victims.map(v=>({v,member:aseanMember(v.country)})).filter(x=>x.member);
  const aseanVictims=regional.map(x=>({...x.v,_member:x.member}));
  const malaysia=aseanVictims.filter(v=>v._member.code==='MY');
  const a24=aseanVictims.filter(v=>withinDays(v.discovered,1)).length,a7=aseanVictims.filter(v=>withinDays(v.discovered,7)).length;
  const my24=malaysia.filter(v=>withinDays(v.discovered,1)).length,my7=malaysia.filter(v=>withinDays(v.discovered,7)).length,my30=malaysia.filter(v=>withinDays(v.discovered,30)).length;
  const countries=countBy(aseanVictims,v=>v._member.name),groups=countBy(aseanVictims,v=>v.group||'Unknown'),sectors=countBy(aseanVictims,v=>v.sector||'Unspecified');
  const myGroups=countBy(malaysia,v=>v.group||'Unknown');
  $('aseanClaimsLoaded').textContent=sourceReady(RW)?fmt(aseanVictims.length):'—';$('aseanClaims24').textContent=sourceReady(RW)?fmt(a24):'—';$('aseanClaims7').textContent=sourceReady(RW)?fmt(a7):'—';$('aseanCountriesActive').textContent=sourceReady(RW)?fmt(countries.length):'—';$('aseanTopCountry').textContent=countries[0]?.name||'—';$('aseanShare').textContent=sourceReady(RW)&&victims.length?`${(aseanVictims.length/victims.length*100).toFixed(1)}%`:'—';
  $('myClaims24').textContent=sourceReady(RW)?fmt(my24):'—';$('myClaims7').textContent=sourceReady(RW)?fmt(my7):'—';$('myClaims30').textContent=sourceReady(RW)?fmt(my30):'—';$('myTopGroup').textContent=myGroups[0]?.name||'—';
  const criticalSignals=Number(MYCERT?.stats?.criticalSignals||0),ransomSignals=Number(MYCERT?.stats?.ransomwareSignals||0);const signal=Math.min(100,my24*18+Math.min(my7,8)*7+Math.min(my30,15)*3+Math.min(criticalSignals,6)*5+Math.min(ransomSignals,3)*8);const level=signal>=70?'HEIGHTENED':signal>=45?'ELEVATED':signal>=20?'GUARDED':'LOW';$('malaysiaSignalScore').textContent=sourceReady(RW)||sourceReady(MYCERT)?signal:'—';$('malaysiaSignalLevel').textContent=level;$('malaysiaSignalLevel').dataset.level=level.toLowerCase();
  const latest=MYCERT?.advisories?.[0];$('malaysiaNarrative').textContent=latest?`${my30} Malaysia ransomware claim${my30===1?'':'s'} appear within 30 days in the loaded feed. Latest MyCERT signal: ${latest.title}`:`${my30} Malaysia ransomware claim${my30===1?'':'s'} appear within 30 days in the loaded feed. MyCERT advisory collection is pending.`;
  const counts=new Map(countries.map(x=>[x.name,x.count]));const max=Math.max(...ASEAN_MEMBERS.map(m=>counts.get(m.name)||0),1);$('aseanCountryGrid').innerHTML=ASEAN_MEMBERS.map(m=>{const n=counts.get(m.name)||0;const pct=n/max*100;return `<div class="asean-country ${m.code==='MY'?'is-malaysia':''}"><div class="country-top"><span class="country-flag">${m.flag}</span><div><strong>${esc(m.name)}</strong><small>${m.code}</small></div><b>${fmt(n)}</b></div><div class="country-meter"><i style="width:${n?Math.max(5,pct):0}%"></i></div><small>${n?'claims in loaded feed':'no claim in loaded feed'}</small></div>`;}).join('');$('aseanMatrixHint').textContent=`${fmt(aseanVictims.length)} regional claims · ${fmt(countries.length)} countries active`;
  $('aseanGroupCount').textContent=`${fmt(groups.length)} groups`;renderRanking('aseanTopGroups',groups,8,true);renderRanking('aseanTopSectors',sectors,8,false);
  renderMycert();
}
function renderMycert(){const ready=sourceReady(MYCERT),feed=$('mycertFeed');if(!ready){$('mycertStatusText').textContent='Run “Update MyCERT Intelligence” in GitHub Actions';feed.innerHTML='<div class="empty-state">Waiting for first MyCERT collection…</div>';return;}const degraded=MYCERT?.meta?.lastAttemptStatus==='failed';$('mycertStatusText').textContent=degraded?'Latest saved data · current refresh degraded':`${fmt(MYCERT.stats?.totalLoaded)} advisories loaded`;
  feed.innerHTML=(MYCERT.advisories||[]).slice(0,10).map(a=>{const u=safeMycertUrl(a.url);return `<a class="mycert-item" href="${esc(u)}" ${u==='#'?'':'target="_blank" rel="noopener"'}><div class="mycert-date"><strong>${esc(a.date||'—')}</strong><span>${esc(a.id||'MYCERT')}</span></div><div class="mycert-copy"><div><span class="mycert-type type-${String(a.type||'advisory').toLowerCase()}">${esc(a.type||'Advisory')}</span>${a.severity?`<span class="mycert-severity">${esc(a.severity)}</span>`:''}</div><strong>${esc(a.title||'MyCERT advisory')}</strong>${a.cves?.length?`<small>${a.cves.map(esc).join(' · ')}</small>`:''}</div><span class="mycert-arrow">↗</span></a>`;}).join('')||'<div class="empty-state">No advisories parsed from MyCERT.</div>';
}


function safeHttpUrl(v){try{const u=new URL(v);return ['http:','https:'].includes(u.protocol)?u.href:'#';}catch{return '#';}}
function asMs(v,dateOnly=false){if(!v)return 0;const raw=dateOnly&&/^\d{4}-\d{2}-\d{2}$/.test(String(v))?`${v}T12:00:00Z`:v;const t=new Date(raw).getTime();return Number.isFinite(t)?t:0;}
function feedTime(e){if(!e.time)return 'Date unavailable';if(e.dateOnly){const d=new Date(e.time);return Number.isNaN(d.getTime())?e.time:d.toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'});}return relTime(e.time);}
function severityRank(v){return({critical:4,high:3,medium:2,low:1,info:0})[String(v||'info').toLowerCase()]??0;}
function normalizeSeverity(v){const x=String(v||'').toUpperCase();return x.includes('CRITICAL')?'critical':x.includes('HIGH')?'high':x.includes('MEDIUM')?'medium':x.includes('LOW')?'low':'info';}
function makeFeedId(parts){return parts.map(x=>String(x??'')).join('|');}
function buildIntelligenceEvents(){
  const events=[];
  const unified=buildUnified();
  const byId=new Map(unified.map(v=>[v.id,v]));

  if(sourceReady(KEV)){
    [...(KEV.vulnerabilities||[])].sort((a,b)=>String(b.dateAdded||'').localeCompare(String(a.dateAdded||''))).slice(0,45).forEach(v=>{
      const u=byId.get(v.id)||v,pri=u.priority?.label||'HIGH',sev=v.ransomware?'critical':normalizeSeverity(pri);
      events.push({id:makeFeedId(['cisa',v.id,v.dateAdded]),source:'CISA KEV',sourceCode:'CISA',kind:v.ransomware?'ransomware':'vulnerability',severity:sev,time:v.dateAdded,dateOnly:true,title:`${v.id} added to CISA KEV`,detail:`${v.vendor||'Unknown vendor'} ${v.product||''}${v.vulnerabilityName?` · ${v.vulnerabilityName}`:''}`,badges:[v.ransomware?'Known ransomware use':null,pri?`CTI ${pri}`:null].filter(Boolean),url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',malaysia:false});
    });
  }

  if(sourceReady(NVD)){
    [...(NVD.vulnerabilities||[])].filter(v=>v.lastModified).sort((a,b)=>asMs(b.lastModified)-asMs(a.lastModified)).slice(0,28).forEach(v=>{
      const sev=normalizeSeverity(v.cvss?.severity),score=v.cvss?.score==null?'No CVSS':`CVSS ${Number(v.cvss.score).toFixed(1)}`;
      events.push({id:makeFeedId(['nvd',v.id,v.lastModified]),source:'NVD CVE API',sourceCode:'NVD',kind:'vulnerability',severity:sev,time:v.lastModified,title:`${v.id} NVD record updated`,detail:`${score} · ${String(v.cvss?.severity||'UNKNOWN').toUpperCase()}${v.description?` · ${v.description.slice(0,180)}`:''}`,badges:[v.vulnStatus||null].filter(Boolean),url:v.sourceUrl,malaysia:false});
    });
  }

  if(sourceReady(EPSS)){
    [...(EPSS.vulnerabilities||[])].sort((a,b)=>Number(b.epss||0)-Number(a.epss||0)).slice(0,12).forEach(v=>{
      const p=Number(v.epss||0),sev=p>=.7?'critical':p>=.5?'high':p>=.1?'medium':'low';
      events.push({id:makeFeedId(['epss',v.id,EPSS.meta?.scoreDate||EPSS.meta?.collectedAt]),source:'FIRST EPSS',sourceCode:'EPSS',kind:'exploitation',severity:sev,time:EPSS.meta?.collectedAt,title:`${v.id} daily EPSS ${(p*100).toFixed(2)}%`,detail:`Estimated probability of exploitation in the next 30 days · ${(Number(v.percentile||0)*100).toFixed(1)} percentile`,badges:[p>=.5?'High exploit probability':'EPSS scored'],url:'https://www.first.org/epss/',malaysia:false});
    });
  }

  if(sourceReady(RW)){
    (RW.victims||[]).slice(0,70).forEach(v=>{
      const member=aseanMember(v.country),isMY=member?.code==='MY';
      events.push({id:makeFeedId(['rw',v.id,v.discovered]),source:'Ransomware OSINT',sourceCode:'RW',kind:'ransomware',severity:isMY?'critical':'high',time:v.discovered,title:`Ransomware claim: ${v.victim||'Unknown victim'}`,detail:`${v.group||'Unknown group'} · ${v.country||'Unknown country'} · ${v.sector||'Unspecified sector'} · public leak-site claim`,badges:[v.group||null,isMY?'Malaysia':member?'ASEAN':null].filter(Boolean),url:safeHttpUrl(v.sourceUrl||v.website),malaysia:isMY});
    });
  }

  if(sourceReady(MYCERT)){
    (MYCERT.advisories||[]).slice(0,35).forEach(a=>{
      const ransomware=String(a.type||'').toUpperCase().includes('RANSOMWARE');
      const sev=ransomware?'critical':normalizeSeverity(a.severity||a.type);
      events.push({id:makeFeedId(['mycert',a.id,a.date]),source:'MyCERT Malaysia',sourceCode:'MY',kind:ransomware?'ransomware':'malaysia',severity:sev,time:a.date,dateOnly:true,title:a.title||'MyCERT advisory',detail:`${a.type||'Advisory'}${a.cves?.length?` · ${a.cves.join(', ')}`:''}`,badges:['Malaysia',a.severity||null].filter(Boolean),url:safeMycertUrl(a.url),malaysia:true});
    });
  }

  return events.filter(e=>e.time).sort((a,b)=>asMs(b.time,b.dateOnly)-asMs(a.time,a.dateOnly)||severityRank(b.severity)-severityRank(a.severity));
}
function matchesFeedFilter(e){if(FEED_FILTER==='all')return true;if(FEED_FILTER==='critical')return e.severity==='critical';if(FEED_FILTER==='ransomware')return e.kind==='ransomware';if(FEED_FILTER==='malaysia')return e.malaysia;if(FEED_FILTER==='vulnerability')return e.kind==='vulnerability'||e.kind==='exploitation';return true;}
function freshnessInfo(label,data,thresholdMin,code){const t=asMs(data?.meta?.collectedAt);if(!t)return{label,code,state:'offline',age:'Not collected',pct:0};const mins=Math.max(0,(Date.now()-t)/60000);const state=mins<=thresholdMin?'fresh':mins<=thresholdMin*2?'aging':'stale';const pct=Math.max(7,Math.min(100,100-(mins/(thresholdMin*2))*100));return{label,code,state,age:mins<60?`${Math.floor(mins)}m ago`:mins<2880?`${Math.floor(mins/60)}h ago`:`${Math.floor(mins/1440)}d ago`,pct};}
function renderFreshness(){const rows=[freshnessInfo('CISA KEV',KEV,60,'C'),freshnessInfo('NVD CVE API',NVD,240,'N'),freshnessInfo('FIRST EPSS',EPSS,2160,'E'),freshnessInfo('Ransomware OSINT',RW,45,'R'),freshnessInfo('MyCERT Malaysia',MYCERT,180,'MY')];$('freshnessList').innerHTML=rows.map(r=>`<div class="fresh-row"><span class="fresh-code">${r.code}</span><div class="fresh-main"><div><strong>${r.label}</strong><span class="fresh-state ${r.state}">${r.state.toUpperCase()}</span></div><div class="fresh-track"><i class="${r.state}" style="width:${r.pct}%"></i></div></div><small>${r.age}</small></div>`).join('');}
function renderUnifiedFeed(){
  const events=buildIntelligenceEvents(),filtered=events.filter(matchesFeedFilter),shown=filtered.slice(0,FEED_LIMIT),now=Date.now();
  const recent24=events.filter(e=>{const t=asMs(e.time,e.dateOnly);return t&&now-t<=86400000&&now-t>=-86400000;}).length;
  $('signals24h').textContent=fmt(recent24);$('criticalSignals').textContent=fmt(events.filter(e=>e.severity==='critical').length);$('ransomwareSignals').textContent=fmt(events.filter(e=>e.kind==='ransomware').length);$('malaysiaSignals').textContent=fmt(events.filter(e=>e.malaysia).length);$('activeSourceCount').textContent=`${[KEV,NVD,EPSS,RW,MYCERT].filter(sourceReady).length} SOURCES`;
  const latest=events[0];$('latestSignalSource').textContent=latest?.source||'—';$('tickerSource').textContent=latest?.sourceCode||'INTELLIGENCE';$('latestSignalTicker').textContent=latest?latest.title:'Waiting for source data…';$('feedUpdatedAt').textContent=new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});$('intelFeedCount').textContent=`${fmt(filtered.length)} correlated signals · newest first`;
  const previous=KNOWN_FEED_IDS;const currentIds=new Set(events.map(e=>e.id));
  $('unifiedIntelFeed').innerHTML=shown.map(e=>{const isNew=previous&&!previous.has(e.id);const url=safeHttpUrl(e.url);const tags=(e.badges||[]).slice(0,3).map(b=>`<span>${esc(b)}</span>`).join('');return `<article class="intel-event sev-${e.severity} ${isNew?'is-new':''}"><div class="event-rail"><span class="event-source source-${String(e.sourceCode).toLowerCase()}">${esc(e.sourceCode)}</span><i></i></div><div class="event-body"><div class="event-top"><div><span class="event-severity">${esc(e.severity.toUpperCase())}</span><span class="event-kind">${esc(String(e.kind).toUpperCase())}</span>${isNew?'<span class="new-signal">NEW</span>':''}</div><time>${esc(feedTime(e))}</time></div><h4>${esc(e.title)}</h4><p>${esc(e.detail||'')}</p>${tags?`<div class="event-tags">${tags}</div>`:''}</div>${url!=='#'?`<a class="event-link" href="${esc(url)}" target="_blank" rel="noopener" aria-label="Open source">↗</a>`:'<span class="event-link muted-link">•</span>'}</article>`;}).join('')||'<div class="empty-state">No signals match this filter.</div>';
  $('feedMore').style.display=filtered.length>FEED_LIMIT?'inline-flex':'none';$('feedWindowHint').textContent=filtered.length>FEED_LIMIT?`Showing ${fmt(Math.min(FEED_LIMIT,filtered.length))} of ${fmt(filtered.length)}`:`Showing all ${fmt(filtered.length)} signals`;
  KNOWN_FEED_IDS=currentIds;renderFreshness();
}


function executiveSourceStates(){
  const myDegraded=sourceReady(MYCERT)&&MYCERT?.meta?.lastAttemptStatus==='failed';
  return [
    {code:'C',name:'CISA KEV',ready:sourceReady(KEV),degraded:false,collected:KEV?.meta?.collectedAt},
    {code:'N',name:'NVD CVE API',ready:sourceReady(NVD),degraded:false,collected:NVD?.meta?.collectedAt},
    {code:'E',name:'FIRST EPSS',ready:sourceReady(EPSS),degraded:false,collected:EPSS?.meta?.collectedAt},
    {code:'R',name:'Ransomware OSINT',ready:sourceReady(RW),degraded:false,collected:RW?.meta?.collectedAt},
    {code:'MY',name:'MyCERT Malaysia',ready:sourceReady(MYCERT),degraded:myDegraded,collected:MYCERT?.meta?.collectedAt}
  ];
}
function regionalSnapshot(){
  const victims=sourceReady(RW)?(RW.victims||[]):[];
  const tagged=victims.map(v=>({v,member:aseanMember(v.country)})).filter(x=>x.member);
  const malaysia=tagged.filter(x=>x.member.code==='MY').map(x=>x.v);
  const asean=tagged.map(x=>x.v);
  const topCountry=countBy(tagged,x=>x.member.name)[0]||null;
  const topGroup=countBy(asean,v=>v.group||'Unknown')[0]||null;
  return {
    my24:malaysia.filter(v=>withinDays(v.discovered,1)).length,
    my7:malaysia.filter(v=>withinDays(v.discovered,7)).length,
    my30:malaysia.filter(v=>withinDays(v.discovered,30)).length,
    aseanLoaded:asean.length,
    asean24:asean.filter(v=>withinDays(v.discovered,1)).length,
    topCountry,topGroup,latestMycert:MYCERT?.advisories?.[0]||null
  };
}
function executivePosture(){
  const unified=buildUnified();
  const critical=unified.filter(x=>x.priority.label==='CRITICAL').length;
  const epssHigh=Number(EPSS?.stats?.epssGe50||0);
  const rw24=Number(RW?.stats?.claims24h||0);
  const score=Math.min(100,Math.round((critical/Math.max(unified.length,1))*1500+Math.min(35,epssHigh/8)+Math.min(30,rw24*2)));
  return {score,label:score>=75?'HEIGHTENED':score>=50?'ELEVATED':score>=25?'GUARDED':'NORMAL',critical,epssHigh,rw24};
}
function topPriorityKevs(limit=5){
  return buildUnified().sort((a,b)=>b.priority.score-a.priority.score||Number(b.epss?.epss||0)-Number(a.epss?.epss||0)).slice(0,limit);
}
function renderExecutiveBriefing(){
  if(!$('executiveWatchlist'))return;
  const posture=executivePosture(),regional=regionalSnapshot(),events=buildIntelligenceEvents(),sources=executiveSourceStates(),top=topPriorityKevs(5);
  const healthy=sources.filter(x=>x.ready&&!x.degraded).length,degraded=sources.filter(x=>x.degraded).length,unavailable=sources.filter(x=>!x.ready).length;
  const confidence=unavailable>=2?'LIMITED':degraded||unavailable?'MODERATE':'HIGH';
  const latest=events[0];
  const topKev=top[0];
  const topGroup=(RW?.topGroups||[])[0]||regional.topGroup;
  $('briefHeadline').textContent=`${posture.label} external threat posture · ${fmt(posture.critical)} critical-priority KEVs`;
  $('briefGeneratedAt').textContent=`Generated ${new Date().toLocaleString()}`;
  $('briefWindow').textContent=latest?`Latest signal: ${feedTime(latest)}`:'Current intelligence window';
  $('briefConfidence').textContent=`Confidence ${confidence}`;
  $('briefConfidence').dataset.level=confidence.toLowerCase();
  $('briefSummary').textContent=`Current external intelligence shows ${fmt(posture.critical)} CISA-known exploited vulnerabilities at Critical CTI priority. ${fmt(posture.epssHigh)} KEVs have EPSS probability at or above 50%, and the latest ransomware feed contains ${fmt(posture.rw24)} public victim claim${posture.rw24===1?'':'s'} discovered within 24 hours. ${regional.my30?`${fmt(regional.my30)} Malaysia claim${regional.my30===1?'':'s'} appear within 30 days in the loaded feed.`:'No Malaysia ransomware claim appears within 30 days in the currently loaded feed.'}`;

  const priorities=[
    {tone:'critical',num:'01',title:'Exploit-priority vulnerabilities',value:fmt(posture.critical),text:topKev?`${topKev.id} currently leads the watchlist at ${topKev.priority.score}/100${topKev.epss?`, EPSS ${(Number(topKev.epss.epss)*100).toFixed(1)}%`:''}${topKev.ransomware?', with known ransomware use':''}.`:'Waiting for correlated KEV intelligence.'},
    {tone:'ransomware',num:'02',title:'Ransomware activity',value:fmt(posture.rw24),text:topGroup?`${topGroup.name||'Unknown'} is the leading group in the currently loaded ranking${topGroup.count!=null?` with ${fmt(topGroup.count)} claim${topGroup.count===1?'':'s'}`:''}. Public leak-site entries are treated as claims, not confirmed incidents.`:'Waiting for ransomware intelligence.'},
    {tone:'regional',num:'03',title:'Malaysia / ASEAN watch',value:fmt(regional.my30),text:regional.latestMycert?`Latest MyCERT signal: ${regional.latestMycert.title}. ASEAN loaded-feed activity currently totals ${fmt(regional.aseanLoaded)} claims.`:`ASEAN loaded-feed activity currently totals ${fmt(regional.aseanLoaded)} claims. MyCERT advisory collection is pending.`}
  ];
  $('briefPriorities').innerHTML=priorities.map(x=>`<div class="brief-priority tone-${x.tone}"><span class="brief-num">${x.num}</span><div><span>${esc(x.title)}</span><strong>${esc(x.value)}</strong><p>${esc(x.text)}</p></div></div>`).join('');

  const recentEvents=events.slice(0,4);
  $('briefChanges').innerHTML=recentEvents.length?recentEvents.map(e=>`<div class="brief-list-item"><i class="brief-dot sev-${e.severity}"></i><div><strong>${esc(e.title)}</strong><small>${esc(e.source)} · ${esc(feedTime(e))}</small></div></div>`).join(''):'<div class="empty-state">No timestamped changes available.</div>';

  const watch=[];
  if(topKev)watch.push(`${topKev.id}: CTI ${topKev.priority.score}/100${topKev.epss?`, EPSS ${(Number(topKev.epss.epss)*100).toFixed(1)}%`:''}${topKev.ransomware?', ransomware-related':''}.`);
  if(topGroup)watch.push(`Monitor ${topGroup.name||topGroup.group||'the leading ransomware group'} activity and changes in country/sector targeting.`);
  if(regional.latestMycert)watch.push(`Review MyCERT: ${regional.latestMycert.title}.`);
  if(degraded)watch.push(`Collection assurance: ${sources.filter(x=>x.degraded).map(x=>x.name).join(', ')} is degraded; last good data is retained.`);
  else if(unavailable)watch.push(`Restore unavailable source${unavailable===1?'':'s'}: ${sources.filter(x=>!x.ready).map(x=>x.name).join(', ')}.`);
  else watch.push('All five collection sources are currently healthy; continue automated monitoring.');
  $('briefWatch').innerHTML=watch.slice(0,4).map((x,i)=>`<div class="brief-list-item watch"><span>${String(i+1).padStart(2,'0')}</span><div><strong>${esc(x)}</strong></div></div>`).join('');

  $('executiveWatchlist').innerHTML=top.length?top.map((v,i)=>{const cv=v.nvd?.cvss||{},ep=v.epss?`${(Number(v.epss.epss)*100).toFixed(1)}%`:'—';return `<div class="watchlist-row"><span class="watch-rank">${String(i+1).padStart(2,'0')}</span><div class="watch-main"><div><strong>${esc(v.id)}</strong><span class="priority p-${v.priority.label.toLowerCase()}">${v.priority.label}</span></div><small>${esc(v.vendor)} · ${esc(v.product)}</small><div class="watch-metrics"><span>CTI <b>${v.priority.score}</b></span><span>CVSS <b>${cv.score==null?'—':Number(cv.score).toFixed(1)}</b></span><span>EPSS <b>${ep}</b></span>${v.ransomware?'<span class="rw-flag">RANSOMWARE</span>':''}</div></div></div>`;}).join(''):'<div class="empty-state">Waiting for vulnerability intelligence…</div>';

  $('regionalBrief').innerHTML=`<div class="regional-brief-kpis"><div><span>Malaysia ≤30d</span><strong>${fmt(regional.my30)}</strong></div><div><span>ASEAN loaded</span><strong>${fmt(regional.aseanLoaded)}</strong></div><div><span>ASEAN ≤24h</span><strong>${fmt(regional.asean24)}</strong></div></div><div class="regional-brief-lines"><p><span>Top country</span><strong>${esc(regional.topCountry?.name||'—')}</strong></p><p><span>Top group</span><strong>${esc(regional.topGroup?.name||'—')}</strong></p><p><span>Latest MyCERT</span><strong>${esc(regional.latestMycert?.title||'Pending collection')}</strong></p></div>`;

  $('briefSourceState').textContent=unavailable?`${healthy} healthy · ${unavailable} unavailable`:degraded?`${healthy} live · ${degraded} degraded`:`${healthy} / 5 healthy`;
  $('briefSourceHealth').innerHTML=sources.map(x=>{const state=!x.ready?'OFFLINE':x.degraded?'DEGRADED':'LIVE';const cls=!x.ready?'offline':x.degraded?'degraded':'live';return `<div class="brief-source-row"><span class="brief-source-code">${x.code}</span><div><strong>${esc(x.name)}</strong><small>${esc(x.collected?relTime(x.collected):'Not collected')}</small></div><b class="brief-source-state ${cls}">${state}</b></div>`;}).join('');
}
function buildExecutiveBriefText(){
  const posture=executivePosture(),regional=regionalSnapshot(),top=topPriorityKevs(3),sources=executiveSourceStates();
  const latest=buildIntelligenceEvents().slice(0,4);
  return [
    'CYBER THREAT INTELLIGENCE — EXECUTIVE BRIEF',
    `Generated: ${new Date().toLocaleString()}`,
    '',
    `Posture: ${posture.label} (${posture.score}/100 external CTI signal)`,
    `Critical-priority KEVs: ${posture.critical}`,
    `KEVs with EPSS ≥50%: ${posture.epssHigh}`,
    `Ransomware claims ≤24h in latest feed: ${posture.rw24}`,
    `Malaysia claims ≤30d in loaded feed: ${regional.my30}`,
    '',
    'TOP WATCHLIST',
    ...top.map((v,i)=>`${i+1}. ${v.id} — CTI ${v.priority.score}/100; CVSS ${v.nvd?.cvss?.score??'—'}; EPSS ${v.epss?`${(Number(v.epss.epss)*100).toFixed(1)}%`:'—'}; ransomware ${v.ransomware?'known':'not known'}`),
    '',
    'LATEST SIGNALS',
    ...latest.map((e,i)=>`${i+1}. ${e.source}: ${e.title} (${feedTime(e)})`),
    '',
    'SOURCE HEALTH',
    ...sources.map(x=>`${x.name}: ${!x.ready?'OFFLINE':x.degraded?'DEGRADED':'LIVE'}`),
    '',
    'Note: public ransomware leak-site entries are claims, not automatically verified incidents. CTI priority is external intelligence prioritisation, not organisational risk.'
  ].join('\n');
}
async function copyExecutiveBrief(){
  const btn=$('copyBrief');
  try{await navigator.clipboard.writeText(buildExecutiveBriefText());btn.textContent='Copied';setTimeout(()=>btn.textContent='Copy brief',1600);}catch{btn.textContent='Copy failed';setTimeout(()=>btn.textContent='Copy brief',1600);}
}

function renderRanking(id,list,limit,numbered){const max=Math.max(...list.map(x=>x.count),1);$(id).innerHTML=list.slice(0,limit).map((x,i)=>`<div class="rank-row">${numbered?`<span class="rank-num">${String(i+1).padStart(2,'0')}</span>`:''}<div class="rank-main"><div><strong>${esc(x.name)}</strong><span>${fmt(x.count)}</span></div><div class="rank-bar"><i style="width:${Math.max(5,x.count/max*100)}%"></i></div></div></div>`).join('')||'<div class="empty-state">No activity data.</div>';}
function renderActivity(data){if(!data.length){$('activityChart').innerHTML='<div class="empty-state">No dated claims in the latest feed.</div>';return;}const w=820,h=230,p=28,max=Math.max(...data.map(x=>x.count),1);const pts=data.map((d,i)=>{const x=p+(i*(w-2*p)/Math.max(data.length-1,1));const y=h-p-(d.count/max)*(h-2*p);return{x,y,d};});const poly=pts.map(p=>`${p.x},${p.y}`).join(' ');const bars=pts.map((p,i)=>{const bw=Math.max(8,(w-2*p)/(data.length*1.8));return`<rect x="${p.x-bw/2}" y="${p.y}" width="${bw}" height="${h-p-p.y}" rx="4" class="chart-bar"/><circle cx="${p.x}" cy="${p.y}" r="4" class="chart-dot"/>`;}).join('');const labels=pts.map((p,i)=>i%Math.ceil(data.length/6)===0||i===data.length-1?`<text x="${p.x}" y="${h-5}" text-anchor="middle">${p.d.date.slice(5)}</text>`:'').join('');$('activityChart').innerHTML=`<svg viewBox="0 0 ${w} ${h}" role="img" aria-label="Recent ransomware claims activity"><defs><linearGradient id="area" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#56e6ff" stop-opacity=".28"/><stop offset="1" stop-color="#56e6ff" stop-opacity="0"/></linearGradient></defs><polyline points="${poly}" class="chart-line"/>${bars}${labels}</svg>`;const first=data[0]?.count||0,last=data[data.length-1]?.count||0;$('rwTrendLabel').textContent=last>first?'RISING':last<first?'EASING':'STEADY';}
function epssMatch(x,f){const p=x.epss?.epss;if(f==='all')return true;if(p==null)return false;return f==='50'?p>=.5:f==='10'?p>=.1:f==='1'?p>=.01:f==='lt1'?p<.01:true;}
function getFiltered(){const q=$('search').value.trim().toLowerCase(),sev=$('severityFilter').value,ep=$('epssFilter').value,pri=$('priorityFilter').value,ran=$('ransomFilter').value;return buildUnified().filter(v=>{const s=String(v.nvd?.cvss?.severity||'UNKNOWN').toUpperCase();const hay=`${v.id} ${v.vendor} ${v.product} ${v.vulnerabilityName} ${v.nvd?.description||''}`.toLowerCase();return(!q||hay.includes(q))&&(sev==='all'||s===sev)&&epssMatch(v,ep)&&(pri==='all'||v.priority.label===pri)&&(ran==='all'||(ran==='yes'?v.ransomware:!v.ransomware));});}
function renderTable(){const items=getFiltered();const pages=Math.max(1,Math.ceil(items.length/PAGE_SIZE));PAGE=Math.min(PAGE,pages);const slice=items.slice((PAGE-1)*PAGE_SIZE,PAGE*PAGE_SIZE);$('resultLabel').textContent=`${fmt(items.length)} matching records · 50 per page`;$('pageLabel').textContent=`Page ${PAGE} of ${pages}`;$('prevPage').disabled=PAGE<=1;$('nextPage').disabled=PAGE>=pages;$('rows').innerHTML=slice.map(v=>{const cv=v.nvd?.cvss||{},score=cv.score==null?'—':Number(cv.score).toFixed(1),sev=String(cv.severity||'UNKNOWN').toUpperCase(),ep=v.epss?`${(Number(v.epss.epss)*100).toFixed(2)}%`:'—';return`<tr><td><strong class="cve">${esc(v.id)}</strong><small>${esc(v.dateAdded||'')}</small></td><td><strong>${esc(v.vendor)}</strong><small>${esc(v.product)}</small></td><td><b class="cvss">${score}</b><span class="sev-badge sev-${sev.toLowerCase()}">${esc(sev)}</span></td><td><strong class="epss">${ep}</strong><small>${v.epss?`${(Number(v.epss.percentile)*100).toFixed(1)} percentile`:''}</small></td><td><span class="pill ${v.ransomware?'pill-red':'pill-green'}">${v.ransomware?'KNOWN':'NOT KNOWN'}</span></td><td><span class="priority p-${v.priority.label.toLowerCase()}">${v.priority.label}</span><small>${v.priority.score}/100</small></td><td class="intel-cell"><strong>${esc(v.vulnerabilityName)}</strong><small>${esc(v.nvd?.description||v.description||'')}</small></td><td class="action-cell">${esc(v.requiredAction||'—')}</td></tr>`;}).join('')||'<tr><td colspan="8" class="empty-state">No records match your filters.</td></tr>';}
async function fetchJson(path){const r=await fetch(`${path}?t=${Date.now()}`,{cache:'no-store'});if(!r.ok)throw new Error(`${path}: HTTP ${r.status}`);return r.json();}
async function load(){const res=await Promise.allSettled(['data/kev.json','data/nvd.json','data/epss.json','data/ransomware.json','data/mycert.json'].map(fetchJson));[KEV,NVD,EPSS,RW,MYCERT]=res.map(x=>x.status==='fulfilled'?x.value:null);NVD_BY_ID=sourceReady(NVD)?new Map((NVD.vulnerabilities||[]).map(v=>[v.id,v])):new Map();EPSS_BY_ID=sourceReady(EPSS)?new Map((EPSS.vulnerabilities||[]).map(v=>[v.id,v])):new Map();renderHeader();renderTopMetrics();renderEpss();renderSeverity();renderVendors();renderRansomware();renderRegional();renderUnifiedFeed();renderExecutiveBriefing();renderTable();}
['search','severityFilter','epssFilter','priorityFilter','ransomFilter'].forEach(id=>$(id).addEventListener(id==='search'?'input':'change',()=>{PAGE=1;renderTable();}));
$('feedFilters').addEventListener('click',e=>{const b=e.target.closest('[data-feed-filter]');if(!b)return;FEED_FILTER=b.dataset.feedFilter;FEED_LIMIT=18;document.querySelectorAll('.feed-filter').forEach(x=>x.classList.toggle('active',x===b));renderUnifiedFeed();});$('feedMore').addEventListener('click',()=>{FEED_LIMIT+=18;renderUnifiedFeed();});$('prevPage').addEventListener('click',()=>{if(PAGE>1){PAGE--;renderTable();document.querySelector('.intelligence-table-card').scrollIntoView({behavior:'smooth',block:'start'});}});$('nextPage').addEventListener('click',()=>{PAGE++;renderTable();document.querySelector('.intelligence-table-card').scrollIntoView({behavior:'smooth',block:'start'});});
if($('copyBrief'))$('copyBrief').addEventListener('click',copyExecutiveBrief);if($('printBrief'))$('printBrief').addEventListener('click',()=>window.print());
load();setInterval(load,5*60*1000);
