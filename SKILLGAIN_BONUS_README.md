# 技能增益加成系统 (Skill Gain Bonus System)

## 功能说明

这个系统为玩家提供每日的技能训练加成。默认情况下，玩家每天可以享受2小时的技能增长点数翻倍加成。

## 特性

- **首次登录激活**: 当天第一次登录时自动开始计时
- **持续计时**: 不管在线与否，时间持续流逝（真实时间）
- **当天有效**: 每天的加成时间只在当天有效，用不完就作废
- **零点自动重置**: 过了午夜0点自动激活第二天的加成
- **双倍点数**: 技能增长时获得2倍点数（不是成功率）
- **可配置**: 可以通过TAG自定义加成时长和倍率
- **彩色提示**: 登录时显示绿色/黄色的剩余时间提示

## 默认设置

- **每日加成时长**: 2小时（真实时间）
- **加成倍率**: 2倍（每次技能增长获得2点而不是1点）
- **重置时间**: 每天零点（00:00）自动激活新的一天

## 自定义配置

你可以通过以下TAG来自定义每个角色的加成设置：

### 设置加成时长（小时）
```
.xset SKILLGAIN_BONUS_HOURS 3
```
这将设置加成时长为3小时

### 设置加成倍率
```
.xset SKILLGAIN_BONUS_MULTIPLIER 3
```
这将设置技能增长速度为3倍

### 禁用加成
```
.xset SKILLGAIN_BONUS_HOURS 0
```
将加成时长设置为0即可禁用

## 全局配置

如果你想为所有玩家设置统一的加成，可以在脚本中使用：

```
[FUNCTION f_onchar_create]
TAG.SKILLGAIN_BONUS_HOURS=2
TAG.SKILLGAIN_BONUS_MULTIPLIER=2
```

或者在 @Login 触发器中设置：

```
ON=@Login
IF (<TAG0.SKILLGAIN_BONUS_HOURS> == 0)
    TAG.SKILLGAIN_BONUS_HOURS=2
    TAG.SKILLGAIN_BONUS_MULTIPLIER=2
ENDIF
```

## 工作原理

### 时间计算逻辑

1. **首次登录**: 当天第一次登录时，记录 `SKILLGAIN_BONUS_STARTTIME`（开始时间戳）
2. **持续计时**: 从开始时间到当前时间，不管玩家是否在线，时间都在流逝
3. **日期判断**: 系统通过比较年月日（YYYYMMDD格式）来判断是否跨天
4. **自动激活**: 过了午夜0点后，下次技能增长时自动激活新一天的加成
5. **加成应用**: 如果还有剩余加成时间，技能增长时获得多倍点数
6. **防止超限**: 技能增长会自动限制在上限值，不会超过
7. **当天作废**: 当天的加成时间用不完就作废，不会累积到第二天

### 实际场景示例

**场景1: 正常使用**
- 08:00 登录 → 开始计时，剩余 2 小时
- 10:00 下线 → 已用 2 小时
- 14:00 再登录 → 显示"已过期"

**场景2: 跨天使用**
- 23:00 登录 → 开始计时，剩余 2 小时
- 23:59 → 第一天的加成只剩 1 分钟（用不完就作废）
- 00:00 → 自动切换到第二天的 2 小时
- 01:00 下线 → 第二天已用 1 小时
- 10:00 再登录 → 显示剩余 1 小时

**场景3: 在线跨天**
- 23:00 登录 → 开始计时
- 一直在线练功到第二天 02:00
- 00:00 时自动切换到第二天的加成（懒加载，在技能增长时检测）
- 02:00 下线 → 第二天已用 2 小时
- 再登录 → 显示"已过期"

## 代码修改位置

- `src/game/chars/CCharSkill.cpp` - Skill_Experience() 函数中添加了加成计算
- `src/game/clients/CClientMsg.cpp` - 登录流程中添加了提示消息

## 示例

### 示例1: VIP玩家3倍加成4小时
```
[FUNCTION f_vip_bonus]
TAG.SKILLGAIN_BONUS_HOURS=4
TAG.SKILLGAIN_BONUS_MULTIPLIER=3
SYSMESSAGE You have VIP status! 3x skill gain for 4 hours!
```

### 示例2: 新手玩家5倍加成24小时
```
ON=@Create
IF (<ACCOUNT.TOTALCONNECTTIME> < 10)
    TAG.SKILLGAIN_BONUS_HOURS=24
    TAG.SKILLGAIN_BONUS_MULTIPLIER=5
ENDIF
```

### 示例3: 周末双倍加成
```
ON=@Login
IF (<SERV.DATETIME.DAYOFWEEK> == 0) || (<SERV.DATETIME.DAYOFWEEK> == 6)
    TAG.SKILLGAIN_BONUS_HOURS=6
    TAG.SKILLGAIN_BONUS_MULTIPLIER=2
    SYSMESSAGE Weekend Bonus: 2x skill gain for 6 hours!
ENDIF
```

## 注意事项

1. **真实时间计时**: 从首次登录开始计时，不管在线与否，时间都在流逝
2. **当天有效**: 每天的加成时间只在当天有效，23点登录只能用到23:59:59
3. **自动跨天**: 过了0点自动激活第二天的加成，无需重新登录
4. **双倍点数**: 加成是技能增长的点数翻倍（例如每次+2点而不是+1点），不是成功率
5. **防止超限**: 技能增长会自动限制在上限值，不会超过
6. **懒加载**: 日期变更检测在技能增长时进行，性能开销最小
7. **安全区域**: 在安全区域内技能不会增长（原有机制保持不变）
8. **彩色提示**: 登录时显示绿色（有剩余）或黄色（已过期）的提示消息

## 查看剩余时间

玩家可以通过以下方式查看加成状态：

```
.show SKILLGAIN_BONUS_STARTTIME
.show SKILLGAIN_BONUS_DAY
```

或者创建一个脚本命令：

```
[FUNCTION f_checkbonus]
LOCAL.BonusMax=<TAG0.SKILLGAIN_BONUS_HOURS>
IF (<LOCAL.BonusMax> == 0)
    LOCAL.BonusMax=2
ENDIF
LOCAL.StartTime=<TAG0.SKILLGAIN_BONUS_STARTTIME>
IF (<LOCAL.StartTime> == 0)
    SYSMESSAGE You haven't activated today's skill gain bonus yet.
    RETURN
ENDIF
LOCAL.CurrentTime=<SERV.GAMETIME>
LOCAL.ElapsedMs=<EVAL <LOCAL.CurrentTime>-<LOCAL.StartTime>>
LOCAL.ElapsedHours=<EVAL <LOCAL.ElapsedMs>/3600000>
LOCAL.BonusRemaining=<EVAL <LOCAL.BonusMax>-<LOCAL.ElapsedHours>>
IF (<LOCAL.BonusRemaining> > 0)
    SYSMESSAGE You have <DLOCAL.BonusRemaining> hours of skill gain bonus remaining today.
ELSE
    SYSMESSAGE Your daily skill gain bonus has expired. It will reset at midnight.
ENDIF
```

## 技术细节

### 存储的TAG变量

- `SKILLGAIN_BONUS_HOURS`: 每天的加成小时数（默认2）
- `SKILLGAIN_BONUS_MULTIPLIER`: 技能增长倍数（默认2）
- `SKILLGAIN_BONUS_DAY`: 当前加成的日期（YYYYMMDD格式）
- `SKILLGAIN_BONUS_STARTTIME`: 当天加成开始的时间戳（毫秒）

### 性能优化

- **懒加载**: 只在技能增长时检查日期变更，不需要定时器
- **无遍历**: 不需要在0点遍历所有玩家，避免性能峰值
- **按需计算**: 只在需要时计算剩余时间，不持续更新
