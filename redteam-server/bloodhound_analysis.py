#!/usr/bin/env python3
"""
BloodHound 数据分析工具
用于解析 SharpHound/bloodhound-python 收集的 JSON 数据，生成可读的分析报告。
帮助 AI Agent 理解 AD 攻击路径和权限关系。
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field
from collections import defaultdict

@dataclass
class BloodHoundData:
    """BloodHound 收集的数据容器"""
    computers: List[Dict] = field(default_factory=list)
    users: List[Dict] = field(default_factory=list)
    groups: List[Dict] = field(default_factory=list)
    domains: List[Dict] = field(default_factory=list)
    gpos: List[Dict] = field(default_factory=list)
    ous: List[Dict] = field(default_factory=list)
    domainsid: Dict = field(default_factory=dict)
    sessions: List[Dict] = field(default_factory=list)
    rdp_sessions: List[Dict] = field(default_factory=list)
    psremote_sessions: List[Dict] = field(default_factory=list)
    localadmin: List[Dict] = field(default_factory=list)
    commonpaths: List[Dict] = field(default_factory=list)
    acl_results: List[Dict] = field(default_factory=dict)
    trust_results: List[Dict] = field(default_factory=list)


class BloodHoundAnalyzer:
    """BloodHound JSON 数据分析器"""

    def __init__(self, data_path: str):
        self.data_path = Path(data_path)
        self.data = BloodHoundData()
        self.domain_cache: Dict[str, Dict] = {}
        self.group_cache: Dict[str, Dict] = {}
        self.user_cache: Dict[str, Dict] = {}
        self.computer_cache: Dict[str, Dict] = {}

    def load_json(self, filename: str) -> Optional[List[Dict]]:
        """加载单个 JSON 文件"""
        filepath = self.data_path / filename
        if not filepath.exists():
            return None
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            try:
                with open(filepath, 'r', encoding='utf-8-sig') as f:
                    return json.load(f)
            except:
                return None

    def load_all(self) -> bool:
        """加载所有 BloodHound JSON 文件"""
        files_map = {
            'computers': 'computers.json',
            'users': 'users.json',
            'groups': 'groups.json',
            'domains': 'domains.json',
            'gpos': 'gpos.json',
            'ous': 'ous.json',
            'domainsid': 'domainsid.json',
            'sessions': 'sessions.json',
            'rdp_sessions': 'rdp_sessions.json',
            'psremote_sessions': 'psremote.json',
            'localadmin': 'localadmins.json',
            'commonpaths': 'commonpaths.json',
        }

        for attr, filename in files_map.items():
            data = self.load_json(filename)
            if data:
                setattr(self.data, attr, data)

        # ACL 和 Trust 可能嵌套在 domains 中
        if self.data.domains:
            self.data.acl_results = self.data.domains
            self.data.trust_results = self.data.domains

        # 构建缓存以加速查询
        self._build_caches()
        return True

    def _build_caches(self):
        """构建数据缓存"""
        for domain in self.data.domains:
            self.domain_cache[domain.get('ObjectIdentifier', '')] = domain

        for group in self.data.groups:
            self.group_cache[group.get('ObjectIdentifier', '')] = group

        for user in self.data.users:
            self.user_cache[user.get('ObjectIdentifier', '')] = user

        for computer in self.data.computers:
            self.computer_cache[computer.get('ObjectIdentifier', '')] = computer

    def analyze(self) -> str:
        """执行完整分析并生成报告"""
        report = []
        report.append("=" * 70)
        report.append("           BLOODHOUND AD 权限图谱分析报告")
        report.append("=" * 70)
        report.append("")

        # 1. 环境概览
        report.append(self._analyze_overview())

        # 2. 高价值目标分析
        report.append(self._analyze_high_value_targets())

        # 3. 会话分析（找活跃用户路径）
        report.append(self._analyze_sessions())

        # 4. 本地管理员分析
        report.append(self._analyze_local_admin())

        # 5. 组关系分析
        report.append(self._analyze_groups())

        # 6. ACL 权限路径分析
        report.append(self._analyze_acl_paths())

        # 7. 域信任关系
        report.append(self._analyze_trusts())

        # 8. GPO 分析
        report.append(self._analyze_gpos())

        # 9. PSRemote/RDP 分析
        report.append(self._analyze_remote_sessions())

        # 10. 攻击路径总结
        report.append(self._analyze_attack_paths())

        report.append("")
        report.append("=" * 70)
        report.append("                    分析报告生成完毕")
        report.append("=" * 70)

        return "\n".join(report)

    def _get_name(self, obj: Dict) -> str:
        """获取对象的显示名称"""
        return obj.get('Properties', {}).get('name', obj.get('ObjectIdentifier', 'Unknown'))

    def _get_type(self, obj: Dict) -> str:
        """获取对象类型"""
        return obj.get('Type', 'Unknown')

    def _analyze_overview(self) -> str:
        """环境概览"""
        lines = []
        lines.append("【1. 环境概览】")
        lines.append("-" * 50)

        lines.append(f"  域数量:      {len(self.data.domains)}")
        lines.append(f"  用户数量:    {len(self.data.users)}")
        lines.append(f"  计算机数量:  {len(self.data.computers)}")
        lines.append(f"  组数量:      {len(self.data.groups)}")
        lines.append(f"  GPO 数量:    {len(self.data.gpos)}")
        lines.append(f"  OU 数量:     {len(self.data.ous)}")
        lines.append(f"  会话记录:    {len(self.data.sessions)}")
        lines.append(f"  本地管理员:  {len(self.data.localadmin)}")

        # 统计启用/禁用用户
        enabled_users = sum(1 for u in self.data.users if u.get('Properties', {}).get('enabled', True))
        disabled_users = len(self.data.users) - enabled_users
        lines.append(f"  启用用户:    {enabled_users}")
        lines.append(f"  禁用用户:    {disabled_users}")

        # 统计域控
        domain_controllers = [c for c in self.data.computers
                             if c.get('Properties', {}).get('operatingsystem', '').lower().find('domain controller') >= 0]
        lines.append(f"  域控制器:    {len(domain_controllers)}")

        lines.append("")
        return "\n".join(lines)

    def _analyze_high_value_targets(self) -> str:
        """高价值目标分析"""
        lines = []
        lines.append("【2. 高价值目标 (High Value Targets)】")
        lines.append("-" * 50)

        high_value_users = [u for u in self.data.users
                           if u.get('HighValue', False)]
        high_value_groups = [g for g in self.data.groups
                            if g.get('HighValue', False)]

        lines.append(f"  高价值用户 ({len(high_value_users)}):")
        for u in high_value_users[:20]:
            name = self._get_name(u)
            lines.append(f"    - {name}")

        if len(high_value_users) > 20:
            lines.append(f"    ... 还有 {len(high_value_users) - 20} 个")

        lines.append("")
        lines.append(f"  高价值组 ({len(high_value_groups)}):")
        for g in high_value_groups:
            name = self._get_name(g)
            members = g.get('Members', [])
            lines.append(f"    - {name} ({len(members)} 成员)")

        lines.append("")
        return "\n".join(lines)

    def _analyze_sessions(self) -> str:
        """会话分析 - 找用户-计算机映射"""
        lines = []
        lines.append("【3. 会话分析 (Session Analysis)】")
        lines.append("-" * 50)

        if not self.data.sessions:
            lines.append("  [无会话数据]")
            lines.append("")
            return "\n".join(lines)

        # 统计每个用户的会话
        user_sessions = defaultdict(list)
        for sess in self.data.sessions:
            source = sess.get('SourceUserIdentifier', '')
            target = sess.get('TargetComputerName', sess.get('TargetComputerId', ''))
            if source:
                user_sessions[source].append(target)

        # 显示有会话的用户
        lines.append(f"  共有 {len(user_sessions)} 个用户有活动会话:")
        for user, targets in sorted(user_sessions.items(), key=lambda x: len(x[1]), reverse=True)[:30]:
            unique_targets = list(set(targets))
            lines.append(f"    {user}:")
            for t in unique_targets[:5]:
                lines.append(f"      -> {t}")
            if len(unique_targets) > 5:
                lines.append(f"      ... 还有 {len(unique_targets) - 5} 台")

        lines.append("")
        return "\n".join(lines)

    def _analyze_local_admin(self) -> str:
        """本地管理员分析"""
        lines = []
        lines.append("【4. 本地管理员分析 (Local Admin Analysis)】")
        lines.append("-" * 50)

        if not self.data.localadmin:
            lines.append("  [无本地管理员数据]")
            lines.append("")
            return "\n".join(lines)

        # 按计算机统计
        computer_admins = defaultdict(list)
        for entry in self.localadmin:
            computer = entry.get('ComputerName', entry.get('ComputerId', ''))
            members = entry.get('Members', [])
            for m in members:
                member_name = m.get('MemberName', m.get('ObjectIdentifier', ''))
                if member_name and member_name != computer:
                    computer_admins[computer].append(member_name)

        lines.append(f"  共有 {len(computer_admins)} 台计算机有本地管理员信息:")
        for comp, admins in sorted(computer_admins.items(), key=lambda x: len(x[1]), reverse=True)[:20]:
            lines.append(f"    {comp} ({len(admins)} 管理员):")
            for admin in admins[:10]:
                lines.append(f"      - {admin}")
            if len(admins) > 10:
                lines.append(f"      ... 还有 {len(admins) - 10} 个")

        lines.append("")
        return "\n".join(lines)

    def _analyze_groups(self) -> str:
        """组关系分析"""
        lines = []
        lines.append("【5. 组关系分析 (Group Membership)】")
        lines.append("-" * 50)

        # 统计各组人数
        group_sizes = []
        for group in self.data.groups:
            name = self._get_name(group)
            members = group.get('Members', [])
            if members:
                group_sizes.append((name, len(members), members))

        # 按人数排序
        group_sizes.sort(key=lambda x: x[1], reverse=True)

        lines.append(f"  共有 {len(group_sizes)} 个非空组:")
        for name, count, members in group_sizes[:20]:
            lines.append(f"    {name}: {count} 成员")

        # 重点关注特权组
        privileged_groups = [g for g in group_sizes
                           if any(kw in g[0].upper() for kw in ['ADMIN', 'DOMAIN ADMIN', 'ENTERPRISE ADMIN',
                                                                   'SCHEMA ADMIN', 'BACKUP', 'PRINT'])]
        if privileged_groups:
            lines.append("")
            lines.append("  特权组:")
            for name, count, _ in privileged_groups:
                lines.append(f"    - {name}: {count}")

        lines.append("")
        return "\n".join(lines)

    def _analyze_acl_paths(self) -> str:
        """ACL 权限路径分析"""
        lines = []
        lines.append("【6. ACL 权限分析 (ACL Analysis)】")
        lines.append("-" * 50)

        # 查找可能导致权限提升的 ACL
        dangerous_ace_types = [
            'WriteDacl', 'WriteOwner', 'WriteProperty',
            'GenericAll', 'GenericWrite', 'AllExtendedRights',
            'ForceChangePassword', 'AddMember'
        ]

        dangerous_acls = []
        for domain in self.data.domains:
            aces = domain.get('Aces', [])
            for ace in aces:
                principal = ace.get('PrincipalSID', ace.get('PrincipalType', ''))
                rights = ace.get('Rights', {})
                for right in dangerous_ace_types:
                    if rights.get(right, False):
                        dangerous_acls.append((principal, right))

        if dangerous_acls:
            lines.append(f"  发现 {len(dangerous_acls)} 条潜在危险 ACL:")
            for principal, right in dangerous_acls[:30]:
                lines.append(f"    - {principal} 可以 {right}")
        else:
            lines.append("  [未发现明显危险的 ACL 配置]")

        lines.append("")
        return "\n".join(lines)

    def _analyze_trusts(self) -> str:
        """域信任关系分析"""
        lines = []
        lines.append("【7. 域信任关系 (Domain Trusts)】")
        lines.append("-" * 50)

        if not self.data.domains:
            lines.append("  [无域数据]")
            lines.append("")
            return "\n".join(lines)

        for domain in self.data.domains:
            name = self._get_name(domain)
            trusts = domain.get('Trusts', [])

            lines.append(f"  域: {name}")
            if trusts:
                for trust in trusts:
                    target = trust.get('TargetDomainName', 'Unknown')
                    direction = trust.get('TrustDirection', '')
                    transitive = trust.get('Transitive', '')
                    lines.append(f"    -> {target}")
                    lines.append(f"       方向: {direction}, 可传递: {transitive}")
            else:
                lines.append("    无信任关系")

        lines.append("")
        return "\n".join(lines)

    def _analyze_gpos(self) -> str:
        """GPO 分析"""
        lines = []
        lines.append("【8. GPO 策略分析 (GPO Analysis)】")
        lines.append("-" * 50)

        if not self.data.gpos:
            lines.append("  [无 GPO 数据]")
            lines.append("")
            return "\n".join(lines)

        lines.append(f"  共有 {len(self.data.gpos)} 个 GPO:")
        for gpo in self.data.gpos[:15]:
            name = gpo.get('Properties', {}).get('name', 'Unknown')
            gpo_id = gpo.get('ObjectIdentifier', '')
            lines.append(f"    - {name} ({gpo_id})")

        lines.append("")
        return "\n".join(lines)

    def _analyze_remote_sessions(self) -> str:
        """远程会话分析 (PSRemote/RDP)"""
        lines = []
        lines.append("【9. 远程管理会话分析 (PSRemote/RDP)】")
        lines.append("-" * 50)

        if self.data.psremote_sessions:
            lines.append(f"  PSRemote 会话: {len(self.data.psremote_sessions)} 条")
            for sess in self.data.psremote_sessions[:10]:
                source = sess.get('SourceUserIdentifier', '')
                target = sess.get('TargetComputerName', '')
                lines.append(f"    {source} -> {target}")

        if self.data.rdp_sessions:
            lines.append(f"  RDP 会话: {len(self.data.rdp_sessions)} 条")
            for sess in self.data.rdp_sessions[:10]:
                source = sess.get('SourceUserIdentifier', '')
                target = sess.get('TargetComputerName', '')
                lines.append(f"    {source} -> {target}")

        if not self.data.psremote_sessions and not self.data.rdp_sessions:
            lines.append("  [无 PSRemote/RDP 会话数据]")

        lines.append("")
        return "\n".join(lines)

    def _analyze_attack_paths(self) -> str:
        """攻击路径总结"""
        lines = []
        lines.append("【10. 攻击路径总结 (Attack Path Summary)】")
        lines.append("-" * 50)

        findings = []

        # 1. 找 Domain Admins 的会话
        da_sessions = []
        for sess in self.data.sessions:
            source = sess.get('SourceUserIdentifier', '')
            if 'ADMIN' in source.upper() or 'DOMAIN' in source.upper():
                target = sess.get('TargetComputerName', '')
                da_sessions.append((source, target))

        if da_sessions:
            findings.append(("CRITICAL", f"发现 {len(da_sessions)} 条域管会话"))
            for user, comp in da_sessions[:5]:
                findings.append(("  ", f"  {user} 登录到 {comp}"))

        # 2. 找本地管理员可以横向移动的主机
        admin_rights = defaultdict(set)
        for entry in self.data.localadmin:
            computer = entry.get('ComputerName', '')
            members = entry.get('Members', [])
            for m in members:
                admin = m.get('MemberName', '')
                if admin:
                    admin_rights[admin].add(computer)

        # 找拥有多台机器管理员权限的用户
        multi_admin = [(user, list(comps)) for user, comps in admin_rights.items() if len(comps) > 1]
        if multi_admin:
            findings.append(("HIGH", f"发现 {len(multi_admin)} 个用户是多台机器的本地管理员"))
            for user, comps in sorted(multi_admin, key=lambda x: len(x[1]), reverse=True)[:5]:
                findings.append(("  ", f"  {user} 可以管理 {len(comps)} 台: {', '.join(comps[:3])}..."))

        # 3. 找可以Kerberoast的用户
        spn_users = [u for u in self.data.users
                    if u.get('Properties', {}).get('hasspn', False)]
        if spn_users:
            findings.append(("MEDIUM", f"发现 {len(spn_users)} 个 SPN 用户 (可 Kerberoast)"))
            for u in spn_users[:5]:
                name = self._get_name(u)
                findings.append(("  ", f"  {name}"))

        # 4. 找 AS-REP Roastable 用户
        asrep_users = [u for u in self.data.users
                      if u.get('Properties', {}).get('dontreqpreauth', False)]
        if asrep_users:
            findings.append(("MEDIUM", f"发现 {len(asrep_users)} 个 AS-REP Roastable 用户"))
            for u in asrep_users[:5]:
                name = self._get_name(u)
                findings.append(("  ", f"  {name}"))

        # 5. 找禁用预认证的用户
        if not findings:
            findings.append(("INFO", "未发现明显的攻击路径"))

        # 输出结果
        for level, msg in findings:
            if level == "CRITICAL":
                lines.append(f"  [CRITICAL] {msg}")
            elif level == "HIGH":
                lines.append(f"  [HIGH] {msg}")
            elif level == "MEDIUM":
                lines.append(f"  [MEDIUM] {msg}")
            else:
                lines.append(f"  {msg}")

        lines.append("")
        return "\n".join(lines)

    @property
    def localadmin(self):
        return self.data.localadmin


def main():
    if len(sys.argv) < 2:
        print("用法: python bloodhound_analysis.py <数据目录>")
        print("示例: python bloodhound_analysis.py ./20260330123456_BloodHound")
        sys.exit(1)

    data_path = sys.argv[1]
    if not os.path.exists(data_path):
        print(f"错误: 路径不存在: {data_path}")
        sys.exit(1)

    analyzer = BloodHoundAnalyzer(data_path)
    if not analyzer.load_all():
        print("警告: 部分文件加载失败，继续分析可用数据...")

    report = analyzer.analyze()
    print(report)


if __name__ == "__main__":
    main()
