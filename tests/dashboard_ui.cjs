/* Offline browser checks. Pass --playwright /module/path and --browser /executable,
 * or use NODE_PATH and Playwright\'s installed browser. No real backend is contacted. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

function option(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
}

async function main() {
  const { chromium } = require(option("--playwright") || "playwright");
  const browser = await chromium.launch({headless: true, executablePath: option("--browser")});
  const page = await browser.newPage();
  const errors = [], requests = [], checks = [];
  const html = fs.readFileSync(path.join(__dirname, "..", "dashboard.html"), "utf8");
  const injection = '<img src=x onerror="window.__injected=true">';
  const fixture = {auth_user_info_raw: {id: "synthetic-import", token: "synthetic-token",
    name: injection, expireTime: 2000000000000}};
  const operations = [];
  let s6 = false;
  let gateway = {queue_enabled: false, queue_max_wait_seconds: 120,
    pool_max_inflight: 0, usage_index_enabled: false, credits_details_enabled: false};
  const account = {uid: "synthetic-details", nickname: injection, realm: "intl",
    enabled: true, credits: {remain: 0, used: 0, size: 0}};
  const campaignId = 'campaign-"\'<img src=x onerror=window.__injected=true>';
  const campaignTasks = [
    {campaign_id: campaignId, uid: account.uid, claimable: true, action_type: "CLAIM_BENEFIT", status: "claimable"},
    {campaign_id: "view", uid: account.uid, claimable: false, action_type: "VIEW_DETAILS", jump_url: "https://example.invalid/details?a=1&b=2"},
    {campaign_id: "bad-link", uid: account.uid, claimable: false, action_type: "VIEW_DETAILS", jump_url: "javascript:window.__injected=true"},
    {campaign_id: "unknown", uid: account.uid, claimable: true, action_type: "UNKNOWN"},
    {campaign_id: "expired", uid: account.uid, claimable: false, action_type: "CLAIM_BENEFIT", status: "expired"},
  ].map((task, index) => ({name: "campaign-" + index + " " + injection,
    description: injection, task_code: "campaign:" + index, current: injection,
    target: injection, reward_credit: injection, reward_energy: injection, ...task}));
  let delayed = null;
  let holdCn = false;
  const done = (name) => checks.push(name);
  page.on("pageerror", error => errors.push(error.message));
  page.on("dialog", dialog => dialog.accept());
  await page.route("**/*", async route => {
    const request = route.request();
    const url = new URL(request.url());
    assert.equal(url.hostname, "dashboard.invalid", "Unexpected external request");
    if (url.pathname === "/") {
      return route.fulfill({contentType: "text/html", body: html});
    }
    let result = {};
    if (url.pathname === "/accounts/import") {
      const body = request.postDataJSON();
      requests.push(body);
      if (body.dryRun && holdCn && body.realm === "cn") {
        delayed = route;
        return;
      }
      const row = {uid: "synthetic-import", reason: injection};
      result = {result: {added: [], updated: [], skipped: [], invalid: [], warnings: []}};
      if (!body.realm) result.result.invalid.push({uid: "synthetic-import", reason: "realm is required " + injection});
      else {
        result.result[body.overwrite ? "updated" : "added"].push(row);
        result.result.warnings.push({uid: "synthetic-import", reason: "latest-" + body.realm + "-" + body.overwrite + " " + injection});
      }
    } else if (url.pathname === "/settings") result = {gateway,
      usage_index: {state: "degraded", last_error: injection, summary: {state: "historical_difference"}, persist_errors: 2}};
    else if (url.pathname === "/settings/save") {
      const body = request.postDataJSON();
      operations.push({path: url.pathname, body});
      gateway = body.gateway;
      result = {ok: true};
    } else if (url.pathname === "/accounts/credits/details") {
      operations.push({path: url.pathname, body: request.postDataJSON()});
      result = {credits_details: {plan_used: null, plan_total: 0, addon_used: 0, addon_total: null,
        total_credits: 0, peak_credits: null, partial: true, stale: true,
        endpoint_status: {[injection]: {status: injection}}}};
    } else if (url.pathname === "/tasks") {
      operations.push({path: url.pathname, realm: url.searchParams.get("realm")});
      result = {tasks: s6 ? campaignTasks : [], accounts: s6 ? [account] : [], summary: {has_checkin: false}};
    } else if (url.pathname === "/tasks/campaign/claim") {
      operations.push({path: url.pathname, body: request.postDataJSON()});
      result = {claimed: false, message: "领取尚未确认，请刷新状态"};
    } else if (url.pathname === "/panel/status") result = {authenticated: true};
    else if (url.pathname === "/realm") result = {current: "cn"};
    else if (url.pathname === "/accounts") result = {accounts: s6 ? [account] : [], credits_details_enabled: s6};
    else if (url.pathname === "/usage/by-account") result = {accounts: []};
    else if (url.pathname === "/v1/models") result = {data: []};
    else if (url.pathname === "/usage/recent") result = {rows: [], total: 0, page: 1, total_pages: 1};
    else if (request.method() !== "GET") throw new Error("Unexpected mutation " + url.pathname);
    return route.fulfill({contentType: "application/json", body: JSON.stringify(result)});
  });
  try {
    await page.goto("http://dashboard.invalid/");
    const chooserPromise = page.waitForEvent("filechooser");
    await page.getByRole("button", {name: "导入账号", exact: true}).click();
    const chooser = await chooserPromise;
    await chooser.setFiles({name: "cockpit-<b>fixture</b>.json", mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(fixture))});
    await page.waitForFunction(() => document.querySelector("#importBody").textContent.includes("realm is required"));
    assert.equal(await page.locator("#btnImportCommit").isDisabled(), true);
    assert.equal(requests.length, 1);
    assert.deepEqual(requests[0].data, [fixture]);
    assert.equal(requests[0].realm, "");
    done("Cockpit single-object file is read; missing realm disables commit");

    await page.locator("#importRealm").selectOption("intl");
    await page.waitForFunction(() => document.querySelector("#importBody").textContent.includes("latest-intl-false"));
    assert.equal(await page.locator("#btnImportCommit").isDisabled(), false);
    assert.equal(requests.at(-1).dryRun, true);
    assert.equal(requests.at(-1).realm, "intl");
    assert.match(await page.locator("#importBody").innerText(), /导入提示/);
    assert.match(await page.locator("#importBody").innerText(), /<img src=x/);
    assert.match(await page.locator("#importBody").innerText(), /<b>fixture<\/b>/);
    assert.equal(await page.locator("#importBody img").count(), 0);
    assert.equal(await page.evaluate(() => window.__injected), undefined);
    done("Region change reruns preview; filename, reasons and warnings remain escaped text");

    holdCn = true;
    await page.locator("#importRealm").selectOption("cn");
    const deadline = Date.now() + 5000;
    while (!delayed && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 5));
    assert.ok(delayed, "Expected delayed region preview request");
    assert.equal(await page.locator("#btnImportCommit").isDisabled(), true);
    await page.locator("#importRealm").selectOption("intl");
    await page.waitForFunction(() => document.querySelector("#importBody").textContent.includes("latest-intl-false"));
    const lateResponse = page.waitForResponse(response => response.url().endsWith("/accounts/import") && response.request().postDataJSON().realm === "cn");
    await delayed.fulfill({contentType: "application/json", body: JSON.stringify({result: {
      added: [], updated: [], skipped: [], invalid: [{uid: "stale", reason: "STALE_PREVIEW"}]}})});
    await lateResponse;
    await page.waitForTimeout(100);
    assert.doesNotMatch(await page.locator("#importBody").innerText(), /STALE_PREVIEW/);
    assert.match(await page.locator("#importBody").innerText(), /latest-intl-false/);
    assert.equal(await page.locator("#btnImportCommit").isDisabled(), false);
    done("Delayed old region response cannot overwrite the newer preview");

    await page.locator("#importOverwrite").check();
    await page.waitForFunction(() => document.querySelector("#importBody").textContent.includes("latest-intl-true"));
    const preview = requests.at(-1);
    assert.equal(preview.dryRun, true);
    assert.equal(preview.overwrite, true);
    const committed = page.waitForRequest(request => request.url().endsWith("/accounts/import") && !request.postDataJSON().dryRun);
    await page.locator("#btnImportCommit").click();
    const commit = (await committed).postDataJSON();
    const {dryRun, ...expected} = preview;
    assert.deepEqual(commit, expected);
    await page.waitForFunction(() => !document.querySelector("#importModal").classList.contains("show"));
    done("Overwrite change reruns preview; commit exactly matches latest preview data and options");
    s6 = true;
    await page.locator("#btnNavSettings").click();
    await page.waitForFunction(() => document.querySelector("#usageIndexStatus").textContent.includes("degraded"));
    assert.match(await page.locator("#usageIndexStatus").innerText(), /历史汇总超出日志范围/);
    assert.match(await page.locator("#usageIndexStatus").innerText(), /记录写入失败 2 次/);
    assert.equal(await page.locator("#usageIndexStatus img").count(), 0);
    await page.locator("#gwQueue").check();
    await page.locator("#gwWait").fill("75");
    await page.locator("#gwInflight").fill("2");
    await page.locator("#gwIndex").check();
    await page.locator("#gwCredits").check();
    await page.locator('[onclick="saveGatewaySettings(this)"]').click();
    await page.waitForFunction(() => document.querySelector("#toastBox").textContent.includes("请求与账号设置已保存"));
    assert.deepEqual(operations.find(item => item.path === "/settings/save").body, {gateway: {
      queue_enabled: true, queue_max_wait_seconds: 75, pool_max_inflight: 2,
      usage_index_enabled: true, credits_details_enabled: true}});
    done("Gateway five fields save with exact types; index degradation and persistence status render safely");

    await page.locator("#btnNavGateway").click();
    await page.locator("#tabIntl").click();
    await page.getByRole("button", {name: "明细", exact: true}).click();
    await page.waitForFunction(() => document.querySelector("#creditsBody").textContent.includes("套餐已用"));
    assert.deepEqual(operations.find(item => item.path === "/accounts/credits/details").body, {uid: account.uid});
    const detailText = await page.locator("#creditsBody").innerText();
    assert.match(detailText, /套餐已用 \/ 总额：暂无数据 \/ 0/);
    assert.match(detailText, /附加已用 \/ 总额：0 \/ 暂无数据/);
    assert.match(detailText, /部分数据暂不可用/);
    assert.match(detailText, /当前显示缓存/);
    assert.ok(detailText.includes(injection));
    assert.equal(await page.locator("#creditsBody img").count(), 0);
    await page.locator("#creditsModal").getByRole("button", {name: "关闭", exact: true}).click();
    done("Credits details use uid; null differs from zero, partial/stale/endpoint status remain visible and escaped");

    await page.waitForFunction(() => document.querySelectorAll("#growthTable tbody tr").length === 5);
    assert.ok(operations.some(item => item.path === "/tasks" && item.realm === "intl"));
    for (const id of ["btnRunTasks", "btnCatTravel", "legacyGrowthSummary"]) {
      assert.equal(await page.locator("#" + id).isVisible(), false);
    }
    assert.equal(await page.locator("#growthTable .campaign-claim").count(), 1);
    assert.equal(await page.locator("#growthTable img").count(), 0);
    assert.equal(await page.locator("#growthTable a").count(), 1);
    assert.equal(await page.locator("#growthTable a").getAttribute("href"), "https://example.invalid/details?a=1&b=2");
    assert.equal(await page.locator("#growthTable a").getAttribute("rel"), "noopener noreferrer");
    const claim = page.locator("#growthTable .campaign-claim");
    assert.equal(await claim.getAttribute("data-campaign"), campaignId);
    await claim.click();
    await page.waitForFunction(() => document.querySelector("#toastBox").textContent.includes("领取尚未确认"));
    const claims = operations.filter(item => item.path === "/tasks/campaign/claim");
    assert.equal(claims.length, 1);
    assert.deepEqual(claims[0].body, {uid: account.uid, campaign_id: campaignId});
    assert.doesNotMatch(await page.locator("#toastBox").innerText(), /领取已确认/);
    assert.equal(await page.locator("#toastBox > div").last().evaluate(element => getComputedStyle(element).color), "rgb(180, 83, 9)");
    assert.equal(await page.evaluate(() => window.__injected), undefined);
    done("International campaigns hide legacy actions; only claimable CLAIM_BENEFIT posts, false claim never reports success, links/text/data remain escaped");
    assert.deepEqual(errors, []);
    const report = {status: "PASS", command: [process.execPath, ...process.argv.slice(1)], exit_status: 0,
      browser: await browser.version(), checks, operations,
      import_requests: requests.map(({data, ...options}) => ({...options, row_count: data.length})), page_errors: errors};
    const reportPath = path.resolve(option("--report") || path.join(__dirname, "..", ".omx/artifacts/p0-p2/S6-dashboard-ui.json"));
    fs.mkdirSync(path.dirname(reportPath), {recursive: true});
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
