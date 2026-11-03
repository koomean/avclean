'use strict';

// Product copy stays local: no analytics, remote scripts, or API calls.
const copy = {
  th: {
    pageTitle: 'avclean — สแกนไฟล์บน Mac ในแบบของคุณ',
    skip: 'ข้ามไปเนื้อหา', navFeatures: 'จุดเด่น', navInstall: 'ติดตั้ง', navGuide: 'วิธีใช้', navFaq: 'คำถามที่พบบ่อย',
    heroRelease: 'เครื่องมือเล็กๆ สำหรับ Mac ของคุณ', heroTitle1: 'สแกน Mac', heroTitle2: 'ในแบบของคุณ.',
    heroDescription: 'ตรวจไฟล์ด้วย ClamAV ผ่าน Terminal ที่ใช้ง่าย เลือกสแกนเมื่อต้องการ เห็นผลชัดเจน และจัดการทุกอย่างได้ในเครื่องของคุณ',
    heroCta: 'เริ่มต้นด้วย Homebrew', heroSecondary: 'ดูวิธีใช้งาน', compatibility: 'macOS · Apple Silicon', freeOpen: 'ฟรีและโอเพนซอร์ส',
    copyInstall: 'คัดลอกคำสั่งติดตั้ง', copyTap: 'คัดลอกคำสั่งตั้งค่า Tap', copyScan: 'คัดลอกคำสั่งสแกน',
    demoTabs: 'ตัวอย่างโปรแกรม', demoMenu: 'เมนู', demoScan: 'ผลสแกน', demoHealth: 'ตรวจระบบ',
    sampleResult: 'ข้อมูลสมมติสำหรับแสดงหน้าตาโปรแกรม', demoCaption: 'ลองสลับดูตัวอย่างหน้าจอโปรแกรม',
    principleLocal: 'ไฟล์อยู่บนเครื่องคุณ', principleDemand: 'เปิดใช้เมื่อต้องการ', principleOpen: 'เปิดซอร์สให้ตรวจสอบ',
    featuresTitle: ['เรียบง่ายตอนใช้', 'ใส่ใจในรายละเอียด'],
    featuresIntro: 'เครื่องมือที่ช่วยให้คุณรู้ว่าสแกนอะไรไปแล้ว และยังมีอะไรที่ต้องตรวจต่อ โดยไม่เพิ่มความวุ่นวายให้ Mac',
    localTitle: ['ไฟล์ของคุณ', 'อยู่กับคุณเสมอ'], localBody: 'สแกนในเครื่องด้วย ClamAV โดยไม่อัปโหลดไฟล์ไปวิเคราะห์ อินเทอร์เน็ตใช้สำหรับอัปเดตฐานข้อมูลภัยคุกคาม',
    coverageTitle: ['ผลลัพธ์ที่บอกได้มากกว่า', 'แค่ “ไม่พบภัยคุกคาม”'], coverageBody: 'แยกไฟล์ที่สแกนแล้ว ข้อผิดพลาด ไฟล์ที่ข้าม และข้อจำกัดของ engine เพื่อให้คุณเห็นเมื่อการสแกนยังไม่ครบ',
    coverageExample: 'ตัวอย่างรายงานสแกนไม่ครบ', coverageIncomplete: 'สแกนไม่ครบ · มีรายการให้ตรวจต่อ', coverageScanned: 'ไฟล์ที่สแกนแล้ว', coverageError: 'ข้อผิดพลาด', coverageSkipped: 'ไฟล์ที่ข้าม', illustration: 'ตัวอย่างการแสดงผล',
    workersTitle: 'ใช้ทรัพยากรอย่างพอดี', workersBody: 'เริ่มต้นด้วย workers สูงสุด 4 งานตามจำนวน performance cores และใช้ engine เดิมซ้ำระหว่างเปิดเมนู ปรับเองได้ด้วย --jobs',
    quarantineTitle: 'คุณตัดสินใจก่อนกักกัน', quarantineBody: 'ยืนยันก่อนย้ายไฟล์ เก็บตำแหน่งเดิมไว้ใน manifest และตรวจว่าไฟล์ไม่ได้เปลี่ยนหลังสแกน พร้อมป้องกันชื่อไฟล์ชนกัน',
    checkTitle: 'ตรวจความพร้อมได้เอง', checkBody: 'ใช้ doctor ตรวจระบบ หรือ self-test ทดสอบการตรวจจับด้วย signature จำลองที่ไม่เป็นอันตราย แบบไม่ต้องต่ออินเทอร์เน็ต',
    installTitle: ['ติดตั้ง avclean.', 'แล้วเรียก av ได้เลย.'], installDescription: 'เปิด Terminal แล้วเริ่มด้วยคำสั่งนี้ ไม่ต้องสมัครบัญชี ไม่ต้องตั้งค่า engine ด้วยตัวเอง',
    requirements: ['สำหรับ macOS บน Apple Silicon', 'ต้องติดตั้ง Homebrew ไว้ก่อน'], brewHelp: 'ยังไม่มี Homebrew? ดูวิธีติดตั้ง', installTabs: 'วิธีติดตั้ง', installFirst: 'ติดตั้งครั้งแรก', installShort: 'อยากใช้ชื่อสั้น?',
    stepInstall: 'ติดตั้งแพ็กเกจ', stepUpdate: 'เตรียมฐานข้อมูลล่าสุด', stepRun: 'เปิดเมนู แล้วเลือกสิ่งที่ต้องการสแกน', installFooter: 'เลือกไฟล์สำเร็จรูปให้อัตโนมัติเมื่อมีรุ่นที่เข้ากัน',
    shortDescription: 'ตั้งค่า Tap ครั้งเดียว แล้วใช้ brew install avclean ได้เลย เครื่องที่เคยติดตั้งจาก Tap นี้แล้วใช้ชื่อสั้นได้ทันที',
    shortFootnote: 'Homebrew 6+ ต้องใช้ brew trust ส่วนรุ่นเก่าข้ามบรรทัดนี้ได้ แพ็กเกจนี้เผยแพร่ผ่าน koomean/tap ยังไม่ได้อยู่ใน homebrew/core',
    guideTitle: ['เมนูก็ง่าย', 'คำสั่งก็คล่อง'], guideIntro: 'เปิด av เพื่อใช้เมนู 1–7 หรือพิมพ์คำสั่งตรงๆ ให้เข้ากับวิธีทำงานของคุณ',
    cmdScanTitle: 'สแกนโฟลเดอร์ที่เลือก', cmdScanBody: 'เปลี่ยน path เป็นไฟล์หรือโฟลเดอร์ของคุณ', cmdQuickTitle: 'สแกนพื้นที่ที่ใช้บ่อย', cmdQuickBody: 'Downloads, Desktop และ Documents',
    cmdDoctorTitle: 'ตรวจความพร้อมของระบบ', cmdDoctorBody: 'ตรวจ engine, การเชื่อมต่อภายใน และฐานข้อมูล', cmdTestTitle: 'ทดสอบการตรวจจับแบบออฟไลน์', cmdTestBody: 'ใช้ไฟล์และ signature จำลองที่ไม่เป็นอันตราย',
    guideMore: 'เลือกจำนวน workers เองด้วย --jobs หรือดูคำสั่งทั้งหมดด้วย av --help', guideDocs: 'อ่านคู่มือฉบับเต็ม',
    openTitle: 'ดูได้ทุกบรรทัด พัฒนาต่อได้ทุกคน', openDescription: 'แอพโอเพนซอร์สภายใต้ MIT พร้อมชุดทดสอบ regression 84 รายการในรุ่น 2.1.2 และ build ที่ทดสอบบน macOS 15 และ 26', openCta: 'เปิด GitHub',
    faqTitle: 'ก่อนเริ่มใช้งาน', faqIntro: 'เรื่องที่ควรรู้เกี่ยวกับเครื่องมือเล็กๆ ตัวนี้',
    faq1q: 'รองรับ Mac รุ่นไหนบ้าง?', faq1a: 'รุ่นนี้รองรับ macOS บน Apple Silicon (ชิปตระกูล M) ยังไม่รองรับ Intel หรือ Linux มีไฟล์ติดตั้งสำเร็จรูปที่ทดสอบบน macOS 15 และ 26 หาก build จากซอร์สต้องมี Xcode Command Line Tools ที่เข้ากับ macOS ของคุณ',
    faq2q: 'สแกนตลอดเวลาอยู่เบื้องหลังไหม?', faq2a: 'ไม่ใช่ระบบป้องกันแบบ real-time คุณเป็นคนเลือกเริ่มสแกนเอง โดย engine ส่วนตัวจะถูกใช้ซ้ำระหว่างเปิดเมนูและปิดเมื่อออกจากโปรแกรม ไฟล์ที่ไม่พบภัยคุกคามไม่ได้หมายความว่าปลอดภัยจากภัยทุกชนิด และผลตรวจอาจมี false positive ได้',
    faq3q: 'จำเป็นต้องใช้อินเทอร์เน็ตไหม?', faq3a: 'ใช้ตอนติดตั้งและอัปเดตฐานข้อมูล ClamAV เท่านั้น เมื่อมีฐานข้อมูลแล้วสามารถสแกนในเครื่องได้ ไฟล์ที่สแกนไม่ถูกอัปโหลด ส่วน doctor และ self-test ทำงานแบบออฟไลน์ได้',
    faq4q: 'ทำไมบางไฟล์จึงสแกนไม่ครบ?', faq4a: 'สิทธิ์ macOS, symbolic links, ไฟล์ cloud ที่ยังไม่ดาวน์โหลด, ไฟล์ใหญ่กว่า 2047 MiB หรือข้อจำกัดของ engine อาจทำให้มีไฟล์ที่ข้ามหรือข้อผิดพลาด โปรแกรมจะแจ้งแยกไว้ การให้ Terminal มี Full Disk Access ช่วยลดข้อผิดพลาดจากสิทธิ์ได้ ส่วน Full scan ครอบคลุม /Users, /Applications, /Library, /opt และ /usr/local',
    faq5q: 'พบไฟล์ต้องสงสัยแล้วจะเกิดอะไรขึ้น?', faq5a: 'โปรแกรมจะแสดงผลให้ตรวจสอบ และถามก่อนย้ายไฟล์ไปกักกันเมื่อใช้แบบ interactive ไฟล์กักกันเริ่มต้นอยู่ใน ~/quarantine พร้อม manifest เก็บตำแหน่งเดิม คุณควรตรวจผลก่อนตัดสินใจเพราะอาจเป็น false positive',
    faq6q: 'อัปเดตหรือลบโปรแกรมอย่างไร?', faq6a: 'ใช้ av update เพื่ออัปเดตฐานข้อมูล ส่วนตัวแอพอัปเดตด้วย brew update แล้วตามด้วย brew upgrade avclean หากต้องการลบใช้ brew uninstall avclean การตั้งค่า ฐานข้อมูล และ log ใน ~/.av รวมถึงไฟล์กักกันยังถูกเก็บไว้',
    footerTagline: 'เครื่องมือที่เรียบง่าย สำหรับ Mac ของคุณ', footerReleases: 'รุ่นที่เผยแพร่', footerIssues: 'แจ้งปัญหา', footerSecurity: 'ความปลอดภัย', footerLicenses: 'สิทธิ์การใช้งานส่วนประกอบ', backTop: 'กลับด้านบน ↑',
    copied: 'คัดลอกคำสั่งแล้ว', copyFailed: 'คัดลอกไม่สำเร็จ โปรดเลือกคำสั่งแล้วคัดลอกด้วยตัวเอง', menuOpen: 'เปิดเมนู', menuClose: 'ปิดเมนู'
  },
  en: {
    pageTitle: 'avclean — Your Mac. Your files. Your call.',
    skip: 'Skip to content', navFeatures: 'Features', navInstall: 'Install', navGuide: 'How to use', navFaq: 'FAQ',
    heroRelease: 'A little tool for your Mac', heroTitle1: 'Your Mac.', heroTitle2: 'Your call.',
    heroDescription: 'ClamAV scanning, made approachable. Choose what to scan, get a clear picture of the results, and keep your files right on your Mac.',
    heroCta: 'Get started with Homebrew', heroSecondary: 'See how it works', compatibility: 'macOS · Apple Silicon', freeOpen: 'Free & open source',
    copyInstall: 'Copy install command', copyTap: 'Copy tap setup commands', copyScan: 'Copy scan command',
    demoTabs: 'Application preview', demoMenu: 'The menu', demoScan: 'Scan results', demoHealth: 'Self-test', sampleResult: 'Illustrative output, not a live scan', demoCaption: 'Switch tabs to explore the app',
    principleLocal: 'Your files stay local', principleDemand: 'Run it when you need it', principleOpen: 'Open code you can inspect',
    featuresTitle: ['Simple on the surface.', 'Considered underneath.'], featuresIntro: 'Know what was scanned and what still needs your attention. A focused tool that fits the way you use your Mac.',
    localTitle: ['Your files.', 'Still your files.'], localBody: 'ClamAV scans locally. Your files are never uploaded for analysis. Internet access is used to keep threat definitions up to date.',
    coverageTitle: ['There’s more to a scan', 'than “no threats found.”'], coverageBody: 'See scanned files, errors, skipped items, and engine limits separately. If coverage is incomplete, the report says so.',
    coverageExample: 'Example incomplete scan report', coverageIncomplete: 'Incomplete · items need attention', coverageScanned: 'Files scanned', coverageError: 'Errors', coverageSkipped: 'Skipped', illustration: 'Illustrative report',
    workersTitle: 'A measured use of resources', workersBody: 'Defaults to up to 4 workers based on your performance-core count. One private engine is reused while the menu is open. Choose your own limit with --jobs.',
    quarantineTitle: 'You make the quarantine call', quarantineBody: 'Review detections before moving anything. A manifest records original paths, changed files are refused, and filename collisions are handled safely.',
    checkTitle: 'Confidence you can check', checkBody: 'Run doctor to check the setup, or use the offline self-test to verify detection with a harmless generated signature and temporary files.',
    installTitle: ['Install avclean.', 'Make yourself at home.'], installDescription: 'Open Terminal and start here. No account to create. No scanning engine to configure by hand.',
    requirements: ['For macOS on Apple Silicon', 'Homebrew must be installed first'], brewHelp: 'New to Homebrew? Get it here', installTabs: 'Installation method', installFirst: 'First install', installShort: 'Prefer the short name?',
    stepInstall: 'Install the package', stepUpdate: 'Get the latest definitions', stepRun: 'Run av and choose what to scan', installFooter: 'Homebrew uses a compatible prebuilt bottle when available',
    shortDescription: 'Set up the tap once, then use brew install avclean. Already installed from this tap? The short name works right away.',
    shortFootnote: 'Homebrew 6+ requires brew trust; older versions can skip that line. The package is distributed through koomean/tap and is not part of homebrew/core.',
    guideTitle: ['A friendly menu.', 'A familiar command line.'], guideIntro: 'Run av for the seven-option menu, or use a direct command to fit your workflow.',
    cmdScanTitle: 'Scan a chosen folder', cmdScanBody: 'Replace the path with your own files or folders', cmdQuickTitle: 'Check your usual places', cmdQuickBody: 'Downloads, Desktop, and Documents',
    cmdDoctorTitle: 'Check the setup', cmdDoctorBody: 'Inspect the engine, local transport, and database', cmdTestTitle: 'Verify detection offline', cmdTestBody: 'Uses a harmless generated signature and temporary files',
    guideMore: 'Set concurrency with --jobs, or run av --help for all commands.', guideDocs: 'Read the full guide',
    openTitle: 'Every line open. Everyone welcome.', openDescription: 'An MIT-licensed app with 84 regression tests in v2.1.2, plus native builds tested on macOS 15 and 26.', openCta: 'View on GitHub',
    faqTitle: 'A few things to know', faqIntro: 'The practical details before your first scan.',
    faq1q: 'Which Macs are supported?', faq1a: 'This release supports macOS on Apple Silicon (M-series chips). Intel and Linux are not supported. Prebuilt bottles are tested on macOS 15 and 26. Source builds require Xcode Command Line Tools compatible with your macOS version.',
    faq2q: 'Does it run protection in the background?', faq2a: 'This is an on-demand scanner, not real-time protection. You choose when to start a scan. Its private engine is reused while the menu is open and stopped on quit. A clean scan cannot prove safety from every threat, and detections can be false positives.',
    faq3q: 'Does it need an internet connection?', faq3a: 'For installation and signature updates. With definitions downloaded, scans run locally and your scanned files are not uploaded. Both doctor and self-test work offline.',
    faq4q: 'Why might a scan be incomplete?', faq4a: 'macOS permissions, symlinks, undownloaded cloud placeholders, files over 2047 MiB, or engine limits can cause skipped files or errors. These are reported separately. Full Disk Access for Terminal can reduce permission errors. Full scan covers /Users, /Applications, /Library, /opt, and /usr/local.',
    faq5q: 'What happens to a detected file?', faq5a: 'Review the result first. In an interactive session, av asks before moving detections to quarantine. The default location is ~/quarantine, with a manifest of original paths. Review detections carefully: false positives are possible.',
    faq6q: 'How do I update or uninstall?', faq6a: 'Run av update for signature updates. For the app, use brew update followed by brew upgrade avclean. Remove the app with brew uninstall avclean. Configuration, signatures, and logs under ~/.av, plus quarantined files, are kept.',
    footerTagline: 'A little tool for your Mac.', footerReleases: 'Releases', footerIssues: 'Report an issue', footerSecurity: 'Security', footerLicenses: 'Third-party notices', backTop: 'Back to top ↑',
    copied: 'Command copied', copyFailed: 'Could not copy. Select the command and copy it manually.', menuOpen: 'Open navigation', menuClose: 'Close navigation'
  }
};

let language = 'th';
let toastTimer;
const languageButton = document.getElementById('language-toggle');
const menuButton = document.getElementById('menu-toggle');
const navigation = document.getElementById('main-nav');

function applyLanguage(nextLanguage) {
  language = nextLanguage === 'en' ? 'en' : 'th';
  const strings = copy[language];
  document.documentElement.lang = language;
  document.title = strings.pageTitle;
  document.querySelectorAll('[data-i18n]').forEach(element => {
    const value = strings[element.dataset.i18n];
    if (value === undefined) return;
    if (Array.isArray(value)) {
      const nodes = [];
      value.forEach((line, index) => {
        if (index) nodes.push(document.createElement('br'));
        nodes.push(document.createTextNode(line));
      });
      element.replaceChildren(...nodes);
    } else {
      element.textContent = value;
    }
  });
  document.querySelectorAll('[data-i18n-label]').forEach(element => {
    const value = strings[element.dataset.i18nLabel];
    if (value) element.setAttribute('aria-label', value);
  });
  document.querySelectorAll('[data-copy]:not([data-i18n-label])').forEach(button => {
    button.setAttribute('aria-label', `${language === 'th' ? 'คัดลอก' : 'Copy'} ${button.dataset.copy}`);
  });
  languageButton.textContent = language === 'th' ? 'EN' : 'ไทย';
  languageButton.setAttribute('aria-label', language === 'th' ? 'Switch to English' : 'เปลี่ยนเป็นภาษาไทย');
  menuButton.setAttribute('aria-label', strings[menuButton.getAttribute('aria-expanded') === 'true' ? 'menuClose' : 'menuOpen']);
}

try {
  const requested = new URLSearchParams(window.location.search).get('lang');
  const saved = localStorage.getItem('avclean-language');
  applyLanguage(requested === 'en' || requested === 'th' ? requested : saved);
} catch {
  applyLanguage('th');
}

languageButton.addEventListener('click', () => {
  applyLanguage(language === 'th' ? 'en' : 'th');
  try { localStorage.setItem('avclean-language', language); } catch { /* The preference is optional. */ }
});

function showToast(message) {
  const toast = document.getElementById('copy-toast');
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.add('is-visible');
  toastTimer = setTimeout(() => { toast.classList.remove('is-visible'); }, 2400);
}

document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      const icon = button.querySelector('use');
      icon.setAttribute('href', '#i-check');
      button.classList.add('is-copied');
      showToast(copy[language].copied);
      setTimeout(() => {
        icon.setAttribute('href', '#i-copy');
        button.classList.remove('is-copied');
      }, 1800);
    } catch {
      showToast(copy[language].copyFailed);
    }
  });
});

function setupTabs(attribute, prefix) {
  const tabs = [...document.querySelectorAll(`[${attribute}]`)];
  function select(tab) {
    tabs.forEach(item => {
      const selected = item === tab;
      item.setAttribute('aria-selected', String(selected));
      item.tabIndex = selected ? 0 : -1;
      document.getElementById(`${prefix}-${item.getAttribute(attribute)}`).hidden = !selected;
    });
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => { select(tab); });
    tab.addEventListener('keydown', event => {
      let next;
      if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = tabs.length - 1;
      if (next !== undefined) {
        event.preventDefault();
        select(tabs[next]);
        tabs[next].focus();
      }
    });
  });
}

setupTabs('data-demo', 'demo');
setupTabs('data-install', 'install');

function closeMenu() {
  navigation.classList.remove('is-open');
  menuButton.setAttribute('aria-expanded', 'false');
  menuButton.setAttribute('aria-label', copy[language].menuOpen);
}

menuButton.addEventListener('click', () => {
  const open = menuButton.getAttribute('aria-expanded') !== 'true';
  menuButton.setAttribute('aria-expanded', String(open));
  menuButton.setAttribute('aria-label', copy[language][open ? 'menuClose' : 'menuOpen']);
  navigation.classList.toggle('is-open', open);
});
navigation.querySelectorAll('a').forEach(link => { link.addEventListener('click', closeMenu); });
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && menuButton.getAttribute('aria-expanded') === 'true') {
    closeMenu();
    menuButton.focus();
  }
});
