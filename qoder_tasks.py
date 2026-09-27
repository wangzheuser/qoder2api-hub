"""qoder_tasks.py —— Qoder 每日签到、额度与福利包自动化引擎

对应 WorkBuddy 网关的 wb_tasks（成长任务中心），Qoder 的“日常任务中心”是：

1. 每日签到 (daily check-in)：查状态 -> 未签则领取（100 积分），
   409 ALREADY_CLAIMED 归一化为“今日已签到”。
2. Pro 升级包 (pro-upgrade)：一次性 +1800 积分，eligibility -> claim。
3. 额度与套餐：quota/usage 聚合、user/plan 套餐名。
4. 为看板合成“任务行”视图（status/current/target/reward_credit），
   让签到中心复用与成长任务一致的表格渲染。
5. 严格遵守 >= 1.0s 防风控间隔，并使用 qoder_fingerprint 的稳定设备指纹。
"""
import time
import urllib.parse

import qoder_accounts
from qoder_accounts import get_realm_config

_log = lambda msg: None


def set_logger(fn):
    """把任务诊断路由到调用方的日志器（端点吞错时依然可见）。"""
    global _log
    _log = fn or (lambda msg: None)


# ---------------------------------------------------------------------------
# 单账号：状态聚合
# ---------------------------------------------------------------------------
def fetch_task_view(account):
    """为一个账号合成看板任务视图。

    返回 (tasks, summary)：
      tasks   - [ {task_code, name, description, status, current, target,
                   reward_credit, reward_energy} ]
      summary - {streak_days, energy, travel:{state, ...}, plan}

    官方能力门控：签到与 Pro 福利包仅国内版 (has_checkin) 提供；
    国际版返回空任务 + 说明（额度/套餐仍然可查）。
    """
    tasks = []
    summary = {
        "streak_days": 0,
        "energy": 0,
        "travel": {"state": "unknown"},
        "plan": account.plan or "-",
        "credits": account.credits or {},
        "realm": account.realm,
    }

    if not get_realm_config(account.realm)["has_checkin"]:
        if account.fetch_credits().get("ok"):
            summary["energy"] = account.credits.get("remain", 0)
        account.fetch_plan()
        summary["plan"] = account.plan or summary["plan"]
        return tasks, summary

    # --- 每日签到 ---
    ok, st = account.checkin_status()
    if ok:
        summary["streak_days"] = st["streak_days"]
        if st["today_checked_in"]:
            status = "claimed"
            current, target = 1, 1
            desc = "今日已签到，明日再来（连续 %d 天，累计 %d 天）" % (
                st["streak_days"], st["total_claim_days"])
        elif st["active"]:
            status = "completed"      # CLAIMABLE -> 待领奖
            current, target = 1, 1
            desc = "可领取 %d 积分（连续 %d 天，累计 %d 天）" % (
                st["reward_credits"] or 100, st["streak_days"],
                st["total_claim_days"])
        else:
            status, current, target = "not_accepted", 0, 1
            desc = "官方签到活动当前未开放 (status=%s)" % (st.get("status") or "?")
        tasks.append({
            "task_code": "daily_checkin",
            "name": "每日签到",
            "description": desc,
            "jump_url": get_realm_config(account.realm)["website"] + "/",
            "status": status,
            "current": current,
            "target": target,
            "reward_credit": st["reward_credits"] or 100,
            "reward_energy": 0,
        })
    else:
        tasks.append({
            "task_code": "daily_checkin",
            "name": "每日签到",
            "description": "签到状态查询失败: %s" % st,
            "status": "not_accepted",
            "current": 0,
            "target": 1,
            "reward_credit": 100,
            "reward_energy": 0,
        })

    # --- Pro 升级包（一次性福利） ---
    ok2, elig = account.pro_eligibility()
    if ok2:
        if elig:
            p_status, p_cur = "completed", 1     # 待领取
            p_desc = "一次性 Pro 升级包，可领取 +1800 积分"
        else:
            p_status, p_cur = "claimed", 1       # 已领取或活动结束
            p_desc = "已领取或当前不可领取"
        tasks.append({
            "task_code": "pro_upgrade",
            "name": "Pro 升级包",
            "description": p_desc,
            "status": p_status,
            "current": p_cur,
            "target": 1,
            "reward_credit": 1800,
            "reward_energy": 0,
        })
    else:
        tasks.append({
            "task_code": "pro_upgrade",
            "name": "Pro 升级包",
            "description": "eligibility 查询失败: %s" % elig,
            "status": "not_accepted",
            "current": 0,
            "target": 1,
            "reward_credit": 1800,
            "reward_energy": 0,
        })

    # --- 额度卡片（energy -> 积分余额；travel -> 福利包状态） ---
    if account.credits:
        summary["energy"] = account.credits.get("remain", 0)
    else:
        account.fetch_credits()
        summary["energy"] = (account.credits or {}).get("remain", 0)
    if ok2 and elig:
        summary["travel"] = {"state": "arrived", "reward_credit": 1800}
    else:
        summary["travel"] = {"state": "idle", "daily_limit_reached": True}

    account.fetch_plan()
    summary["plan"] = account.plan or summary["plan"]
    return tasks, summary


def fetch_tasks_view(pool, realm=None, uid=None, credits_service=None):
    """看板 /tasks 聚合：选定账号的任务行 + 全部可签账号列表。

    日签到与通用活动分别门控；通用活动只在明细功能开启时按需查询。
    """
    if not pool or not pool.accounts:
        return {"tasks": [], "summary": {}, "accounts": [],
                "msg": "未找到可用账号"}
    eligible = [a for a in pool.accounts
                if a.enabled and a.access_token
                and (not realm or a.realm == realm)
                and (get_realm_config(a.realm)["has_checkin"] or credits_service is not None)]
    if not eligible:
        return {"tasks": [], "summary": {}, "accounts": [],
                "msg": "未找到可用的任务账号"}
    acc = None
    if uid and uid != "all":
        target = pool.get(uid)
        if target and target in eligible:
            acc = target
        else:
            return {"tasks": [], "summary": {}, "accounts": [], "msg": "指定账号不属于所选区域或已停用"}
    if acc is None:
        acc = eligible[0]
    if get_realm_config(acc.realm)["has_checkin"]:
        tasks, summary = fetch_task_view(acc)
    else:
        tasks, summary = [], {"realm": acc.realm, "credits": acc.credits or {}, "plan": acc.plan}
    summary["has_checkin"] = get_realm_config(acc.realm)["has_checkin"]
    if credits_service is not None:
        details = credits_service.details(acc)
        summary["credits_details"] = details
        for campaign in details.get("campaigns") or []:
            campaign_id = campaign.get("campaignId")
            if not campaign_id:
                continue
            status = campaign.get("claimStatus")
            action = campaign.get("actionType")
            now = time.time()
            active = (not campaign.get("startAt") or campaign["startAt"] <= now) and (
                not campaign.get("endAt") or now < campaign["endAt"])
            claimable = (active and campaign.get("validity_valid", True)
                         and status == "CLAIMABLE" and action == "CLAIM_BENEFIT"
                         and details.get("endpoint_status", {}).get("campaigns", {}).get("status") == "supported")
            url = str(campaign.get("url") or "")
            try:
                parsed = urllib.parse.urlsplit(url)
                if parsed.scheme not in ("http", "https") or not parsed.hostname:
                    url = ""
            except ValueError:
                url = ""
            tasks.append({"task_code": "campaign:" + campaign_id, "campaign_id": campaign_id,
                          "uid": acc.uid, "name": campaign.get("name") or campaign_id,
                          "description": campaign.get("description") or "",
                          "status": "claimed" if status == "CLAIMED" else "completed" if claimable else "not_accepted",
                          "claimable": claimable, "action_type": action, "jump_url": url,
                          "current": 1 if claimable or status == "CLAIMED" else 0,
                          "target": 1, "reward_credit": 0, "reward_energy": 0})
    acct_list = [{"uid": a.uid, "nickname": a.nickname or a.uid[:8],
                  "realm": a.realm} for a in eligible]
    return {"tasks": tasks, "summary": summary, "account": acc.public(),
            "accounts": acct_list}


# ---------------------------------------------------------------------------
# 单账号：签到执行
# ---------------------------------------------------------------------------
def run_checkin(account, gap=1.0):
    """为一个账号执行签到闭环。返回 {ok, logs, earned_credit, credits}。"""
    logs = []
    name = account.nickname or account.uid[:8]
    logs.append(f"开始为账号 [{name}] 执行每日签到...")

    if not get_realm_config(account.realm)["has_checkin"]:
        logs.append("! 该区域不支持签到")
        return {"ok": False, "logs": logs, "earned_credit": 0}

    # Account.checkin() 内部已带状态前置与 DISABLED 守卫（不硬 claim）
    res2 = account.checkin()
    earned = 0
    if res2.get("ok"):
        if res2.get("disabled"):
            logs.append(f"— [{name}] {res2.get('msg')}，本次跳过")
            return {"ok": True, "logs": logs, "earned_credit": 0,
                    "credits": account.credits}
        if res2.get("already"):
            logs.append(f"✓ [{name}] {res2.get('msg')}")
        else:
            earned = int(res2.get("reward_credits") or 0)
            logs.append(f"✓ [{name}] 签到成功 +{earned} 积分（连续 {res2.get('streak_days', '-')} 天）")
    else:
        logs.append(f"! [{name}] 签到失败: {res2.get('error')}")
        return {"ok": False, "logs": logs, "earned_credit": 0}

    # 签到后刷新额度与套餐快照（发放有秒级延迟，失败不影响签到结果）
    time.sleep(gap)
    if account.fetch_credits().get("ok"):
        remain = account.credits.get("remain", 0)
        logs.append(f"  当前额度余额: {remain}")
    account.fetch_plan()
    return {"ok": True, "logs": logs, "earned_credit": earned,
            "credits": account.credits}


def run_pro_claim(account):
    """领取一次性 Pro 升级包（+1800）。"""
    logs = []
    name = account.nickname or account.uid[:8]
    ok, elig = account.pro_eligibility()
    if not ok:
        logs.append(f"! [{name}] Pro 升级包资格查询失败: {elig}")
        return {"ok": False, "logs": logs, "earned_credit": 0}
    if not elig:
        logs.append(f"— [{name}] Pro 升级包不可领取（已领或活动未开放）")
        return {"ok": True, "logs": logs, "earned_credit": 0}
    res = account.pro_claim()
    earned = 0
    if res.get("ok"):
        logs.append(f"✓ [{name}] {res.get('msg')}")
        time.sleep(1.0)
        if account.fetch_credits().get("ok"):
            logs.append(f"  当前额度余额: {account.credits.get('remain', 0)}")
        earned = 1800
    else:
        logs.append(f"! [{name}] Pro 升级包领取失败: {res.get('error')}")
    return {"ok": bool(res.get("ok")), "logs": logs, "earned_credit": earned,
            "credits": account.credits}


# ---------------------------------------------------------------------------
# 批量：看板「一键签到领积分」/「领取福利包」
# ---------------------------------------------------------------------------
def run_batch_checkin(targets, gap=1.0, inter_gap=1.5):
    """批量签到。返回 {ok, logs, credit_added, accounts_count}。"""
    combined, total, done = [], 0, 0
    for i, acc in enumerate(targets):
        nick = acc.nickname or acc.uid[:8]
        combined.append("====== 正在为账号 [%s (%s)] 执行每日签到 (%d/%d) ======"
                        % (nick, acc.uid, i + 1, len(targets)))
        res = run_checkin(acc, gap=gap)
        total += res.get("earned_credit") or 0
        done += 1 if res.get("ok") else 0
        for line in res.get("logs") or []:
            combined.append("  " + line)
        if i < len(targets) - 1:
            time.sleep(inter_gap)
    combined.append("====== 全部 %d 个账号签到完毕，累计新增积分: +%d ======"
                    % (len(targets), total))
    for line in combined:
        _log(line)
    return {"ok": done > 0, "logs": combined, "credit_added": total,
            "accounts_count": len(targets)}


def run_batch_pro_claim(targets, gap=1.0, inter_gap=1.5):
    """批量领取福利包。返回 {ok, logs, credit_added, accounts_count, results}。"""
    combined, total, results = [], 0, []
    for i, acc in enumerate(targets):
        nick = acc.nickname or acc.uid[:8]
        res = run_pro_claim(acc)
        total += res.get("earned_credit") or 0
        msg = (res.get("logs") or [""])[-1]
        results.append({"uid": acc.uid, "nickname": nick,
                        "action": "pro_claim", "msg": msg,
                        "reward_credit": res.get("earned_credit") or 0})
        for line in res.get("logs") or []:
            combined.append(line)
        if i < len(targets) - 1:
            time.sleep(inter_gap)
    summary_msg = "\n".join(f"{r['nickname']}: {r['msg']}" for r in results)
    return {"ok": True, "logs": combined, "credit_added": total,
            "accounts_count": len(targets), "results": results,
            "msg": summary_msg}


# ---------------------------------------------------------------------------
# 保活（token refresh 巡检）
# ---------------------------------------------------------------------------
def run_keepalive(pool, force=False, threshold_seconds=4 * 3600):
    """刷新凭证：force=True 刷新全部；否则只刷新剩余寿命不足阈值的账号。

    返回 {refreshed, failed, logs}。
    """
    logs, refreshed, failed = [], 0, 0
    now = time.time()
    for acc in list(pool.accounts if pool else []):
        if not acc.enabled or not acc.access_token:
            continue
        remain = (acc.expires_at or 0) - now
        if not force and remain > threshold_seconds:
            continue
        nick = acc.nickname or acc.uid[:8]
        if force or remain <= threshold_seconds:
            logs.append(f"账号 [{nick}] Token 剩余 {_fmt_eta(remain)}，执行主动保活刷新...")
            if acc.refresh():
                refreshed += 1
                logs.append(f"✓ 账号 [{nick}] Token 保活刷新成功（{_fmt_eta((acc.expires_at or 0) - time.time())}）")
            else:
                failed += 1
                logs.append(f"! 账号 [{nick}] Token 保活刷新失败: {acc.last_error}")
            time.sleep(1.0)
    if not logs:
        logs.append("所有账号 Token 均未临近过期，无需刷新")
    for line in logs:
        _log(line)
    return {"refreshed": refreshed, "failed": failed, "logs": logs}


def _fmt_eta(seconds):
    if seconds <= 0:
        return "已过期"
    if seconds >= 86400:
        return "%.1f 天" % (seconds / 86400)
    if seconds >= 3600:
        return "%.1f 小时" % (seconds / 3600)
    return "%d 分钟" % int(seconds / 60)
