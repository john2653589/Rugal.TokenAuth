using Microsoft.Extensions.Options;
using Rugal.TokenAuth.Core.Interface;
using Rugal.TokenAuth.Core.Model;
using System.Text.RegularExpressions;

namespace Rugal.TokenAuth.Core.Service;

public abstract class UserNameAuthServiceBase<TModel, TResult>
    where TModel : UserNameRegisterModel
{
    protected readonly ArgonService ArgonService;
    protected readonly TokenService TokenService;
    protected readonly IUserQueryer UserQueryer;
    protected readonly SecurePolicySetting SecurePolicySetting;
    protected readonly Dictionary<object, string> Messages;
    public UserNameAuthServiceBase(
        ArgonService ArgonService,
        TokenService TokenService,
        IUserQueryer UserQueryer,
        IOptions<SecurePolicySetting> SecurePolicyOption)
    {
        this.TokenService = TokenService;
        this.ArgonService = ArgonService;
        this.UserQueryer = UserQueryer;

        SecurePolicySetting = SecurePolicyOption.Value ?? new SecurePolicySetting();
        SecurePolicySetting.SpecialCharRegex ??= "[!@#$%^&*(),.?\":{}|]";
        SecurePolicySetting.FilterCharRegex = @"[\s<>]";
        Messages = [];
        InitMessage();
    }

    #region Public Method
    public RegisterResult<TResult> Register(TModel Model, bool IsVerifySecurePolicy = true)
    {
        Model.UserName = Model.UserName.ToUpper();
        if (!Model.Secure.SequenceEqual(Model.ReSecure))
        {
            return new RegisterResult<TResult>()
            {
                Message = GetMessages(RegisterStatusType.SecureDifferent),
                Status = RegisterStatusType.SecureDifferent
            };
        }
        Array.Clear(Model.ReSecure, 0, Model.ReSecure.Length);

        var IsUserNameNotExist = CheckUserNameExist(Model);
        if (!IsUserNameNotExist)
            return new RegisterResult<TResult>()
            {
                Message = GetMessages(RegisterStatusType.UserNameExist),
                Status = RegisterStatusType.UserNameExist,
            };

        if (IsVerifySecurePolicy)
        {
            var PolicyResult = VerifySecurePolicy(Model);
            if (!PolicyResult.Success)
                return new RegisterResult<TResult>()
                {
                    Status = RegisterStatusType.PolicyVerifyFails,
                    Policy = PolicyResult.Status,
                    Message = PolicyResult.Message,
                };
        }

        var HashResult = ArgonService.GenerateHash(Model.Secure);
        var CreateStatus = CreateUser(Model, HashResult, out var Result);
        return new RegisterResult<TResult>()
        {
            Status = CreateStatus,
            Message = GetMessages(CreateStatus),
            Result = Result
        };
    }
    public LoginResult Login(UserNameLoginModel Model, out AuthTokens Tokens)
    {
        Tokens = null;
        Model.UserName = Model.UserName.ToUpper();

        var QueryStatus = QueryUserSecure(Model, out var User, out var Messages);
        if (QueryStatus != LoginStatusType.Success)
        {
            var LoginMessage = GetMessages(QueryStatus);
            if (Messages is not null && Messages.Count > 0)
                LoginMessage.Add(Model.UserName);

            return new LoginResult()
            {
                Status = QueryStatus,
                Message = LoginMessage,
            };
        }

        var IsVerify = ArgonService.VerifyHash(Model.Secure, User.Hash, User.Salt);
        Array.Clear(Model.Secure, 0, Model.Secure.Length);
        if (!IsVerify)
            return new LoginResult()
            {
                Status = LoginStatusType.HashVerifyFails,
                Message = GetMessages(LoginStatusType.HashVerifyFails),
            };

        var Claims = UserQueryer.QueryUserClaims(User.UserId);
        Tokens = TokenService.GenerateAuthTokens(User.UserId, Claims);
        return new LoginResult()
        {
            Status = LoginStatusType.Success,
            Message = GetMessages(LoginStatusType.Success),
            Tokens = Tokens,
        };
    }
    public ResetSecureResult ResetSecure(Guid UserId, ResetSecureModel Model, bool IsVerifySecurePolicy = true)
    {
        if (!Model.Secure.SequenceEqual(Model.ReSecure))
        {
            return new ResetSecureResult()
            {
                Message = GetMessages(ResetSecureType.SecureDifferent),
                Status = ResetSecureType.SecureDifferent,
            };
        }
        Array.Clear(Model.ReSecure, 0, Model.ReSecure.Length);

        if (IsVerifySecurePolicy)
        {
            var PolicyResult = VerifySecurePolicy(Model);
            if (!PolicyResult.Success)
                return new ResetSecureResult()
                {
                    Status = ResetSecureType.PolicyVerifyFails,
                    Policy = PolicyResult.Status,
                    Message = PolicyResult.Message,
                };
        }

        var HashResult = ArgonService.GenerateHash(Model.Secure);
        var ResetResult = ResetUserSecure(UserId, HashResult);
        return new ResetSecureResult()
        {
            Status = ResetResult,
            Message = GetMessages(ResetResult),
        };
    }
    public AuthTokens RefreshTokens(Guid UserId)
    {
        var Result = TokenService.RefreshTokens(UserId);
        return Result;
    }
    #endregion

    #region Protected Message Method
    protected virtual void InitMessage()
    {
        Messages.TryAdd(SecurePolicyType.Success, "Policy verify success.");
        Messages.TryAdd(SecurePolicyType.MinLength, "The minimum secure length is {0}.");
        Messages.TryAdd(SecurePolicyType.MaxLength, "The maximum secure length is {0}.");
        Messages.TryAdd(SecurePolicyType.Digital, "Secure must contain a digit.");
        Messages.TryAdd(SecurePolicyType.UpperCase, "Secure must contain an uppercase letter.");
        Messages.TryAdd(SecurePolicyType.LowerCase, "Secure must contain an lowercase letter.");
        Messages.TryAdd(SecurePolicyType.SpecialChar, "Secure must contain a special character.");
        Messages.TryAdd(SecurePolicyType.FilterChar, "Secure contains invalid characters.");

        Messages.TryAdd(RegisterStatusType.Success, "Registration successful.");
        Messages.TryAdd(RegisterStatusType.SecureDifferent, "Secure different.");
        Messages.TryAdd(RegisterStatusType.UserNameExist, "Username already taken.");
        Messages.TryAdd(RegisterStatusType.PolicyVerifyFails, "Policy verification failed.");
        Messages.TryAdd(RegisterStatusType.PhoneFormatVerifyFails, "Invalid phone number format.");
        Messages.TryAdd(RegisterStatusType.EmailFormatVerifyFails, "Invalid email address format.");
        Messages.TryAdd(RegisterStatusType.Error, "Unexpected error occurred.");

        Messages.TryAdd(ResetSecureType.Success, "Reset secure successful.");
        Messages.TryAdd(ResetSecureType.SecureDifferent, "Secure different.");
        Messages.TryAdd(ResetSecureType.PolicyVerifyFails, "Policy verification failed.");
        Messages.TryAdd(ResetSecureType.Error, "Unexpected error occurred.");

        Messages.TryAdd(LoginStatusType.Success, "Login successful.");
        Messages.TryAdd(LoginStatusType.UserLock, "Account is locked.");
        Messages.TryAdd(LoginStatusType.UserDisable, "Account is disabled.");
        Messages.TryAdd(LoginStatusType.UserNotFound, "User not found.");
        Messages.TryAdd(LoginStatusType.HashVerifyFails, "Password verification failed.");
    }
    #endregion

    #region Protected Verify Method
    protected virtual SecurePolicyResult VerifySecurePolicy(SecureModel Model)
    {
        var Result = new SecurePolicyResult();
        if (SecurePolicySetting.MinLength > 0)
            if (Model.Secure.Length < SecurePolicySetting.MinLength)
            {
                var Message = string.Format(GetMessage(SecurePolicyType.MinLength), SecurePolicySetting.MinLength);
                Result.Status.Add(SecurePolicyType.MinLength);
                Result.Message.Add(Message);
            }

        if (SecurePolicySetting.MaxLength > 0)
            if (Model.Secure.Length > SecurePolicySetting.MaxLength)
            {
                var Message = string.Format(GetMessage(SecurePolicyType.MaxLength), SecurePolicySetting.MaxLength);
                Result.Status.Add(SecurePolicyType.MaxLength);
                Result.Message.Add(Message);
            }

        if (SecurePolicySetting.Digital)
            if (!Regex.IsMatch(Model.Secure, @"\d"))
            {
                var Message = GetMessage(SecurePolicyType.Digital);
                Result.Status.Add(SecurePolicyType.Digital);
                Result.Message.Add(Message);
            }

        if (SecurePolicySetting.UpperCase)
            if (!Regex.IsMatch(Model.Secure, "[A-Z]"))
            {
                var Message = GetMessage(SecurePolicyType.UpperCase);
                Result.Status.Add(SecurePolicyType.UpperCase);
                Result.Message.Add(Message);
            }

        if (SecurePolicySetting.LowerCase)
            if (!Regex.IsMatch(Model.Secure, "[a-z]"))
            {
                var Message = GetMessage(SecurePolicyType.LowerCase);
                Result.Status.Add(SecurePolicyType.LowerCase);
                Result.Message.Add(Message);
            }

        if (SecurePolicySetting.SpecialChar && !string.IsNullOrWhiteSpace(SecurePolicySetting.SpecialCharRegex))
            if (!Regex.IsMatch(Model.Secure, SecurePolicySetting.SpecialCharRegex))
            {
                var Message = GetMessage(SecurePolicyType.SpecialChar);
                Result.Status.Add(SecurePolicyType.SpecialChar);
                Result.Message.Add(Message);
            }

        if (SecurePolicySetting.FilterChar && !string.IsNullOrWhiteSpace(SecurePolicySetting.FilterCharRegex))
            if (Regex.IsMatch(Model.Secure, SecurePolicySetting.FilterCharRegex))
            {
                var Message = GetMessage(SecurePolicyType.FilterChar);
                Result.Status.Add(SecurePolicyType.FilterChar);
                Result.Message.Add(Message);
            }

        Result.Success = Result.Status.Count == 0 && Result.Message.Count == 0;
        return Result;
    }
    protected List<string> GetMessages(params object[] MessageKeys)
    {
        var MessageList = new List<string>();
        foreach (var Key in MessageKeys)
        {
            if (Messages.TryGetValue(Key, out var Message))
                MessageList.Add(Message);
        }
        return MessageList;
    }
    protected string GetMessage(object MessageKey)
    {
        if (Messages.TryGetValue(MessageKey, out var Message))
            return Message;

        return null;
    }
    #endregion

    #region Protected Abstract Method
    protected abstract LoginStatusType QueryUserSecure(UserNameLoginModel Model, out UserSecureModel User, out List<string> Messages);
    protected abstract RegisterStatusType CreateUser(TModel Model, GenerateHashResult HashResult, out TResult Result);
    protected abstract ResetSecureType ResetUserSecure(Guid UserId, GenerateHashResult HashResult);
    protected abstract bool CheckUserNameExist(UserNameLoginModel Model);
    #endregion
}