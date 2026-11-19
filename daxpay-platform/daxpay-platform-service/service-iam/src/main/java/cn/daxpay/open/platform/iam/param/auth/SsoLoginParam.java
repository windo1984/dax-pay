package cn.daxpay.open.platform.iam.param.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/// # 统一认证 ticket 登录参数
@Data
public class SsoLoginParam {

    /// ft-iam 签发的一次性 ticket
    @Schema(description = "统一认证 ticket")
    private String ticket;
}
