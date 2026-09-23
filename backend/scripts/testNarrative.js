const { loadAttckData, getDefaultAttckPath } = require('../src/attckParser');
const { mapAlertsBatch } = require('../src/mapper');
const { buildAttackChains, buildCoverageMatrix } = require('../src/chainBuilder');

const a = loadAttckData(getDefaultAttckPath());
const sample = [
  {
    title: 'APT 攻击案例 1',
    text:
      '在2025年4月的一次网络安全事件中，Lazarus 采用了多种战术和技术对目标组织进行了攻击。初始访问（TA0001）阶段，攻击者利用了Exchange服务器中的一个已知漏洞CVE-2023-1234 (T1190)，该漏洞允许远程代码执行，使得攻击者能够进入目标网络。与此同时，他们还实施了鱼叉式钓鱼邮件附件(T1566.001)策略，向目标组织内部的特定成员发送带有恶意软件的邮件，企图通过社会工程学手段获得网络访问权限，这也是初始访问战术的一部分。一旦获得了初步立足点，为了确保不被发现，攻击者转向防御规避（TA0005）战术，采用进程镂空技术(T1055.012)将恶意代码注入到合法的Office应用程序进程中，如Word或Excel，从而避免安全软件的检测。这一步骤不仅帮助攻击者隐藏了他们的存在，也为后续行动奠定了基础。随后，攻击者运用了横向移动（TA0008）战术，通过SMB协议(T1021.002)在网络内部寻找并感染其他计算机，最终到达数据库服务器。在此过程中，他们部署了勒索软件(T1486)，加密财务系统核心数据库，导致业务中断，这是影响（TA0040）战术的一个实例。最后，为了保证长期控制权，攻击者利用了一个权限提升漏洞CVE-2022-4567完成了持久化（TA0003）驻留，这使得他们即使在系统重启后也能维持对受感染系统的访问权限，确保了即便在网络管理员采取措施之后，攻击者仍能继续其活动。通过这一系列精心策划的步骤，Lazarus 成功地对目标组织造成了重大损害。'
  }
];

const m = mapAlertsBatch(sample, a);
console.log('count', m.length);
m.forEach((x) =>
  console.log(
    x.stepLabel,
    x.timeDisplay,
    x.mapping.primary || '-',
    x.mapping.tacticId,
    x.mapping.tacticName
  )
);
const cov = buildCoverageMatrix(m, a.killChainOrder);
console.log(
  'covered',
  cov.matrix.filter((x) => x.covered).map((x) => x.tacticId).join(',')
);
const chains = buildAttackChains(m);
console.log('duration:', chains[0].durationHuman);
console.log('mode:', chains[0].timeMode);
