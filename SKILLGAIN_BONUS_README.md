# 技能增益加成系统 (Skill Gain Bonus System)

## 功能说明

这个系统为玩家提供每日累计的技能训练加成。默认情况下，玩家每天可以享受累计2小时的技能增长速度翻倍加成。

## 特性

- **每日累计**: 每天累计最多2小时加成时间（无论上下线）
- **零点重置**: 每天零点自动重置加成时间
- **防止超限**: 技能增长不会超过设定的上限值
- **可配置**: 可以通过TAG自定义加成时长和倍率
- **实时提示**: 玩家登录时会看到剩余加成时间

## 默认设置

- **每日加成时长**: 2小时（累计）
- **加成倍率**: 2倍（技能增长几率翻倍）
- **重置时间**: 每天零点（00:00）

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

1. **初始化**: 玩家首次登录或跨越零点时，系统初始化加成计时器
2. **日期判断**: 系统通过比较年月日（YYYYMMDD格式）来判断是否跨天
3. **累计计时**: 在技能训练时，系统累计已使用的加成时间
4. **加成应用**: 如果还有剩余加成时间，技能增长几率会乘以设定的倍率
5. **防止超限**: 技能增长时会检查是否超过上限，例如99.9 + 0.2 会被限制为100.0
6. **零点重置**: 每天零点自动重置，重新获得完整的加成时间
7. **跨登录保持**: 即使下线再上线，已使用的加成时间仍然保留，直到零点重置

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

1. **每日累计**: 加成时间是每天累计的，不是连续的2小时
2. **跨登录保持**: 下线再上线不会重置已使用的加成时间
3. **防止超限**: 技能增长会自动限制在上限值，不会超过（例如99.9 + 0.2 = 100.0）
4. **零点重置**: 每天零点（00:00）自动重置，重新获得完整加成时间
5. **在线计时**: 只有在线时才会消耗加成时间
6. **安全区域**: 在安全区域内技能不会增长（原有机制保持不变）

## 查看剩余时间

玩家可以通过以下方式查看剩余加成时间：

```
.show SKILLGAIN_BONUS_USED
.show SKILLGAIN_BONUS_DAY
```

或者创建一个脚本命令：

```
[FUNCTION f_checkbonus]
LOCAL.BonusMax=<TAG0.SKILLGAIN_BONUS_HOURS>
LOCAL.BonusUsed=<EVAL <TAG0.SKILLGAIN_BONUS_USED>/3600000>
LOCAL.BonusRemaining=<EVAL <LOCAL.BonusMax>-<LOCAL.BonusUsed>>
IF (<LOCAL.BonusRemaining> > 0)
    SYSMESSAGE You have <DLOCAL.BonusRemaining> hours of skill gain bonus remaining today.
ELSE
    SYSMESSAGE Your daily skill gain bonus has been used up.
ENDIF
```
