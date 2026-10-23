// Сквозная проверка окна в настоящем Chromium (puppeteer-core).
// node gui_e2e.js <url> <vcenter> <user> <password> <папка_отчётов> <папка_скриншотов>
const puppeteer = require('puppeteer-core');
const [url, vc, user, pass, outDir, shots] = process.argv.slice(2);
const results = [];
const check = (name, ok, detail = '') => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${!ok && detail ? ' — ' + detail : ''}`); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function setValue(page, name, value) {
  const sel = `[name="${name}"]`;
  await page.waitForSelector(sel);
  await page.$eval(sel, el => { el.focus(); el.select && el.select(); });
  await page.keyboard.down('Control'); await page.keyboard.press('a'); await page.keyboard.up('Control');
  await page.keyboard.press('Backspace');
  await page.type(sel, value);
}
const text = page => page.evaluate(() => document.body.innerText);
async function waitText(page, re, timeout = 30000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeout) { if (re.test(await text(page))) return true; await sleep(100); }
  return false;
}
async function clickText(page, label) {   // клик по чекбоксу/переключателю по подписи
  await page.evaluate(l => {
    const el = [...document.querySelectorAll('label')].find(x => x.innerText.trim().startsWith(l));
    el.querySelector('input').click();
  }, label);
}

(async () => {
  const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium-browser',
    args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1360, height: 1000 });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(url, { waitUntil: 'networkidle2' });
  check('окно открылось', await waitText(page, /Инвентаризация инфраструктуры/));
  check('есть поля подключения и кнопка задания', !!(await page.$('[name="vcenter"]')) && !!(await page.$('#btn-run')));

  // --- подключение: неверный пароль, потом верный
  await setValue(page, 'vcenter', vc);
  await setValue(page, 'user', user);
  await setValue(page, 'password', 'wrong-password');
  await page.click('#btn-connect');
  check('неверный пароль → красный статус', await waitText(page, /Неверный логин или пароль/, 20000));
  await setValue(page, 'password', pass);
  await page.click('#btn-connect');
  check('верный пароль → «Подключено»', await waitText(page, /Подключено: /, 20000));

  // --- долгое задание: окно отвечает, «Остановить» работает
  await setValue(page, 'subnets', '127.0.0.0/22');
  await page.click('#btn-run');
  check('задание запущено', await waitText(page, /Выполняется/, 10000));
  await waitText(page, /Проверено \d+ из 1022/, 20000);
  const t0 = Date.now();
  await clickText(page, 'Дополнительные настройки');
  await page.waitForSelector('[name="ports"]', { timeout: 5000 }).catch(() => null);
  const react = Date.now() - t0;
  check('окно не зависает во время сканирования (отклик < 1 с)', react < 1000, `${react} мс`);
  const live = await page.evaluate(() => document.querySelectorAll('tbody tr').length);
  check('таблица заполняется во время сканирования', live > 0, `строк ${live}`);
  await page.screenshot({ path: `${shots}/running.png` });
  const stop = await page.evaluateHandle(() => [...document.querySelectorAll('button')].find(b => b.innerText.includes('Остановить')));
  await stop.click();
  check('остановка → «Остановлено»', await waitText(page, /Остановлено/, 30000));

  // --- короткое задание до конца
  await page.waitForFunction(() => !document.querySelector('#btn-run').disabled, { timeout: 15000 });
  await setValue(page, 'subnets', '127.0.0.0/29');
  await page.click('#btn-run');
  check('задание выполнено', await waitText(page, /Готово/, 60000));
  const body = await text(page);
  check('в таблице ВМ из vSphere и узлы сети', /vSphere/.test(body) && /127\.0\.0\.1/.test(body));
  await page.type('input[placeholder^="Фильтр"]', '127.0.0.1');
  check('фильтр работает', await waitText(page, /Показано 1 из/, 5000));

  // --- выгрузка (диалога выбора папки на сервере нет → папка из поля)
  await setValue(page, 'export_dir', outDir);
  // всплывающее «Готово…» появляется в правом нижнем углу поверх кнопки — ждём, пока исчезнет совсем (вместе с анимацией)
  await page.waitForFunction(() => !document.querySelector('.pg-toast'), { timeout: 15000 });
  await page.click('#btn-export');
  check('отчёт выгружен', await waitText(page, /Сохранено: inventory_.*\.json/, 15000));
  await page.screenshot({ path: `${shots}/done.png`, fullPage: true });
  await page.setViewport({ width: 420, height: 900 });
  await sleep(400);
  await page.screenshot({ path: `${shots}/narrow.png` });
  check('нет ошибок JavaScript', errors.length === 0, errors.join('; '));
  await browser.close();
  const failed = results.filter(x => !x).length;
  console.log(`\n${results.length - failed}/${results.length} PASS`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
