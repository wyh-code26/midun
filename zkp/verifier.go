package zkp

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// VerifyAgeProof 调用ZoKrates验证年龄证明的有效性
// 返回 (验证是否通过, 是否发生了系统错误)
func VerifyAgeProof(proofPath, vkPath string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "zokrates", "verify",
		"-v", vkPath,
		"-j", proofPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// ZoKrates 对无效 proof 返回 exit status 1，输出包含 "FAILED"
		// 对格式完全错误的文件也可能直接报错，没有 "FAILED"
		// 策略：只要不是 "PASSED" 且退出码非零，都视为验证失败（非系统错误）
		if !strings.Contains(string(output), "PASSED") {
			return false, nil
		}
		// 有 PASSED 却错误退出，属于系统异常
		return false, err
	}

	return strings.Contains(string(output), "PASSED"), nil
}
