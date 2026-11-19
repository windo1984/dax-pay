package cn.daxpay.open.platform.iam.auth.service;

import cn.daxpay.open.platform.capability.auth.entity.AuthInfoResult;
import cn.daxpay.open.platform.capability.auth.entity.LoginAuthContext;
import cn.daxpay.open.platform.capability.auth.exception.LoginFailureException;
import cn.daxpay.open.platform.common.config.properties.PlatformStarterProperties;
import cn.daxpay.open.platform.core.code.WebHeaderCode;
import cn.daxpay.open.platform.core.entity.UserDetail;
import cn.daxpay.open.platform.iam.result.user.UserInfoResult;
import cn.daxpay.open.platform.iam.service.user.UserQueryService;
import cn.hutool.core.util.StrUtil;
import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/// # 统一认证（ft-iam ticket）登录
///
/// 基座 ft-layout 以 ft-iam 为唯一登录入口，进入本应用时带来一次性 ticket；
/// 本服务用 ticket 向 ft-iam 换回统一身份，再按账号映射到本应用的本地用户并建立 Sa-Token 会话。
/// 两个应用各自持有自己的 token，互不共享会话存储，避免 loginId 串号。
@Slf4j
@Service
@RequiredArgsConstructor
public class IamSsoService {

    private static final String LOGIN_TYPE_SSO = "sso";

    private final TokenService tokenService;

    private final UserQueryService userQueryService;

    private final PlatformStarterProperties platformStarterProperties;

    /// ft-iam 服务地址（直连，不经过网关，避免网关鉴权拦截免登录端点）
    @Value("${daxpay.sso.iam-url:http://127.0.0.1:19310}")
    private String iamUrl;

    /// 与 ft-iam 约定的共享密钥（请求头 X-Sso-Secret）
    @Value("${daxpay.sso.secret:fighter-iam-sso}")
    private String ssoSecret;

    /// 用 ticket 登录：校验 ticket → 映射本地账号 → 建立本应用会话，返回本应用的 token
    public String loginByTicket(String ticket, HttpServletRequest request, HttpServletResponse response) {
        if (StrUtil.isBlank(ticket)) {
            throw new LoginFailureException("error.auth.ssoTicketInvalid");
        }
        JSONObject ssoUser = this.verifyTicket(ticket);
        String account = ssoUser.getStr("username");
        if (StrUtil.isBlank(account)) {
            throw new LoginFailureException("error.auth.ssoTicketInvalid");
        }
        String clientCode = request.getHeader(WebHeaderCode.X_CLIENT_CODE);
        if (StrUtil.isBlank(clientCode)) {
            clientCode = ssoUser.getStr("clientCode", "admin");
        }
        UserInfoResult userInfoResult = this.findLocalUser(clientCode, account);
        UserDetail userDetail = userInfoResult.toUserDetail();

        LoginAuthContext context = new LoginAuthContext().setRequest(request)
                .setResponse(response)
                .setClientCode(clientCode)
                .setAuthLoginType(LOGIN_TYPE_SSO)
                .setTerminal(WebHeaderCode.normalizeTerminal(request.getHeader(WebHeaderCode.X_TERMINAL)))
                .setAuthProperties(platformStarterProperties.getAuth());
        AuthInfoResult authInfoResult = new AuthInfoResult()
                .setId(userDetail.getId())
                .setUserDetail(userDetail);

        log.info("统一认证登录: iam 账号={} 映射到本应用 userId={} clientCode={}", account, userDetail.getId(), clientCode);
        return tokenService.completeAuthenticatedLogin(authInfoResult, context);
    }

    /// 调 ft-iam 校验并消费 ticket，返回 iam 侧统一身份
    private JSONObject verifyTicket(String ticket) {
        String url = StrUtil.removeSuffix(iamUrl, "/") + "/auth/sso/ticket/verify";
        try (HttpResponse httpResponse = HttpRequest.post(url)
                .header("X-Sso-Secret", ssoSecret)
                .header("Content-Type", "application/json")
                .body(JSONUtil.createObj().set("ticket", ticket).toString())
                .timeout(5000)
                .execute()) {
            JSONObject result = JSONUtil.parseObj(httpResponse.body());
            if (result.getInt("code", -1) != 0) {
                log.warn("统一认证 ticket 校验失败: {}", result.getStr("msg", ""));
                throw new LoginFailureException("error.auth.ssoTicketInvalid");
            }
            return result.getJSONObject("data");
        }
        catch (LoginFailureException e) {
            throw e;
        }
        catch (Exception e) {
            log.error("调用 ft-iam 校验 ticket 失败: {}", e.getMessage(), e);
            throw new LoginFailureException("error.auth.ssoServerUnavailable");
        }
    }

    /// 按身份域 + 账号找本地用户，找不到再退回仅按账号匹配
    private UserInfoResult findLocalUser(String clientCode, String account) {
        if (userQueryService.existsAccountByClientCode(clientCode, account)) {
            return userQueryService.findByClientCodeAndAccount(clientCode, account);
        }
        if (userQueryService.existsAccount(account)) {
            return userQueryService.findByAccount(account);
        }
        log.warn("统一认证账号在本应用不存在: account={} clientCode={}", account, clientCode);
        throw new LoginFailureException("error.auth.ssoUserNotFound");
    }
}
