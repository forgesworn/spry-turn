// Generated test content only: canvas video, oscillator audio and data packets.
import { pathToFileURL } from 'node:url';
const modulePath = process.env.SPRY_PLAYWRIGHT_PATH;
const { chromium } = await import(modulePath ? pathToFileURL(modulePath).href : 'playwright');
const config = JSON.parse(process.env.SPRY_BROWSER_ICE);
const browser = await chromium.launch({ headless: true, args: ['--autoplay-policy=no-user-gesture-required', '--ignore-certificate-errors'] });
try {
  const page = await browser.newPage();
  await page.goto(process.env.SPRY_BROWSER_ORIGIN);
  for (const iceServer of config) {
    const result = await page.evaluate(async iceServer => {
      const a = new RTCPeerConnection({ iceServers: [iceServer], iceTransportPolicy: 'relay' });
      const b = new RTCPeerConnection({ iceServers: [iceServer], iceTransportPolicy: 'relay' });
      const pendingA = [], pendingB = [];
      a.onicecandidate = e => { if (e.candidate) b.remoteDescription ? b.addIceCandidate(e.candidate) : pendingB.push(e.candidate); };
      b.onicecandidate = e => { if (e.candidate) a.remoteDescription ? a.addIceCandidate(e.candidate) : pendingA.push(e.candidate); };
      const canvas = document.createElement('canvas'); canvas.width = 160; canvas.height = 90;
      const context = canvas.getContext('2d'); let frame = 0;
      const paint = setInterval(() => { context.fillStyle = frame++ % 2 ? '#ed3355' : '#3399cc'; context.fillRect(0, 0, 160, 90); }, 50);
      const stream = canvas.captureStream(20);
      const audio = new AudioContext(); await audio.resume();
      const oscillator = audio.createOscillator(); const destination = audio.createMediaStreamDestination();
      oscillator.connect(destination); oscillator.start();
      for (const track of [...stream.getTracks(), ...destination.stream.getTracks()]) { a.addTrack(track); b.addTrack(track); }
      for (const pc of [a, b]) pc.ontrack = e => {
        const media = document.createElement(e.track.kind === 'video' ? 'video' : 'audio');
        media.autoplay = true; media.muted = true; media.srcObject = new MediaStream([e.track]); document.body.append(media); media.play().catch(() => {});
      };
      const channel = a.createDataChannel('generated');
      let received = false;
      b.ondatachannel = e => { e.channel.onmessage = m => e.channel.send(m.data); };
      channel.onmessage = e => { received = e.data === 'generated-only'; };
      await a.setLocalDescription(await a.createOffer()); await b.setRemoteDescription(a.localDescription);
      for (const c of pendingB) await b.addIceCandidate(c);
      await b.setLocalDescription(await b.createAnswer()); await a.setRemoteDescription(b.localDescription);
      for (const c of pendingA) await a.addIceCandidate(c);
      const until = Date.now() + 20000;
      while (channel.readyState !== 'open' && Date.now() < until) await new Promise(r => setTimeout(r, 30));
      if (channel.readyState !== 'open') throw new Error(`data channel failed: ${a.connectionState}/${b.connectionState}`);
      channel.send('generated-only');
      let evidence;
      while (Date.now() < until) {
        evidence = await Promise.all([a, b].map(async pc => {
          const stats = [...(await pc.getStats()).values()];
          const pair = stats.find(s => s.type === 'candidate-pair' && s.nominated && s.state === 'succeeded');
          const local = pair && stats.find(s => s.id === pair.localCandidateId);
          const remote = pair && stats.find(s => s.id === pair.remoteCandidateId);
          return { local: local?.candidateType, remote: remote?.candidateType, relayProtocol: local?.relayProtocol,
            framesDecoded: stats.filter(s => s.type === 'inbound-rtp' && s.kind === 'video').reduce((n,s) => n+(s.framesDecoded??0),0),
            audioBytes: stats.filter(s => s.type === 'inbound-rtp' && s.kind === 'audio').reduce((n,s) => n+(s.bytesReceived??0),0) };
        }));
        if (received && evidence.every(e => e.local === 'relay' && e.remote === 'relay' && e.framesDecoded > 0 && e.audioBytes > 0)) break;
        await new Promise(r => setTimeout(r, 50));
      }
      clearInterval(paint); oscillator.stop(); stream.getTracks().forEach(t => t.stop()); destination.stream.getTracks().forEach(t => t.stop());
      await audio.close(); a.close(); b.close(); document.body.replaceChildren();
      if (!received || !evidence.every(e => e.local === 'relay' && e.remote === 'relay' && e.framesDecoded > 0 && e.audioBytes > 0)) throw new Error('missing bidirectional decoded media');
      return { transport: iceServer.urls.split('?')[1] ?? 'tls', dataRoundTrip: received, endpoints: evidence };
    }, iceServer);
    console.log(JSON.stringify(result));
  }
} finally { await browser.close(); }
