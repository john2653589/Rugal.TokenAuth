namespace Rugal.TokenAuth.Core.Model;

public class SecureModel
{
    public char[] Secure { get; set; }
}
public class UserNameLoginModel : SecureModel
{
    public string UserName { get; set; }
}
public class EmailLoginModel
{
    public string Email { get; set; }
    public char[] Secure { get; set; }
}
public class PhoneLoginModel
{
    public string Phone { get; set; }
    public char[] Secure { get; set; }
}
public class UserNameRegisterModel : UserNameLoginModel
{
    public char[] ReSecure { get; set; }
}
public class EmailRegisterModel : EmailLoginModel
{
    public char[] ReSecure { get; set; }
}
public class PhoneRegisterModel : PhoneLoginModel
{
    public char[] ReSecure { get; set; }
}

public class RegisterResult<TResult>
{
    public RegisterStatusType Status { get; set; }
    public List<SecurePolicyType> Policy { get; set; }
    public List<string> Message { get; set; }
    public TResult Result { get; set; }
}
public class ResetSecureModel : SecureModel
{
    public char[] ReSecure { get; set; }
}
public class ResetSecureResult
{
    public ResetSecureType Status { get; set; }
    public List<SecurePolicyType> Policy { get; set; }
    public List<string> Message { get; set; }
}
public class LoginResult
{
    public LoginStatusType Status { get; set; }
    public List<string> Message { get; set; }
    public AuthTokens Tokens { get; set; }
}
public class UserSecureModel
{
    public Guid UserId { get; set; }
    public byte[] Hash { get; set; }
    public byte[] Salt { get; set; }
    public DateTime? LockedAt { get; set; }
}

public class SecurePolicySetting
{
    public int MinLength { get; set; }
    public int MaxLength { get; set; }
    public bool Digital { get; set; }
    public bool UpperCase { get; set; }
    public bool LowerCase { get; set; }
    public bool SpecialChar { get; set; }
    public string SpecialCharRegex { get; set; }
    public bool FilterChar { get; set; }
    public string FilterCharRegex { get; set; }
}
public class SecurePolicyResult
{
    public bool Success { get; set; }
    public List<SecurePolicyType> Status { get; set; } = [];
    public List<string> Message { get; set; } = [];
}

public enum AuthType
{
    UserName,
    Email,
    Phone,
}
public enum SecurePolicyType
{
    Success,
    MinLength,
    MaxLength,
    Digital,
    UpperCase,
    LowerCase,
    SpecialChar,
    FilterChar,
}
public enum LoginStatusType
{
    Success,
    UserLock,
    UserDisable,
    UserNotFound,
    HashVerifyFails,
    Other,
}
public enum RegisterStatusType
{
    Success,
    UserNameExist,
    SecureDifferent,
    PolicyVerifyFails,
    PhoneFormatVerifyFails,
    EmailFormatVerifyFails,
    Error,
}

public enum ResetSecureType
{
    Success,
    SecureDifferent,
    PolicyVerifyFails,
    Error,
}