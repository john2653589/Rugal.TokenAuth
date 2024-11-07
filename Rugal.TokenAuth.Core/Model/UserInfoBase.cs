using Rugal.TokenAuth.Core.Interface;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text.Json;

namespace Rugal.TokenAuth.Core.Model;
public abstract class UserInfoBase : IUserInfo
{
    protected List<Claim> Claims { get; set; }
    public Guid UserId => GetGuid("sub");
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public DateTime TokenExpiredDatetime => GetTokenExpiredDatetime();

    #region Get Property Method
    protected virtual string GetString([CallerMemberName] string PropertyName = null)
    {
        if (!TryGetValue(PropertyName, out var Value))
            return null;

        return Value;
    }
    protected virtual Guid GetGuid([CallerMemberName] string PropertyName = null)
    {
        if (!TryGetValue(PropertyName, out var Value) || !Guid.TryParse(Value, out var ConvertValue))
            return Guid.Empty;

        return ConvertValue;
    }
    protected virtual Guid? GetGuidNull([CallerMemberName] string PropertyName = null)
    {
        if (!TryGetValue(PropertyName, out var Value) || !Guid.TryParse(Value, out var ConvertValue))
            return null;

        return ConvertValue;
    }
    protected virtual bool GetBool([CallerMemberName] string PropertyName = null)
    {
        if (!TryGetValue(PropertyName, out var Value) || !bool.TryParse(Value, out var ConvertValue))
            return false;

        return ConvertValue;
    }
    protected virtual bool? GetBoolNull([CallerMemberName] string PropertyName = null)
    {
        if (!TryGetValue(PropertyName, out var Value) || !bool.TryParse(Value, out var ConvertValue))
            return null;

        return ConvertValue;
    }
    protected virtual int GetInt([CallerMemberName] string PropertyName = null)
    {
        if (!TryGetValue(PropertyName, out var Value) || !int.TryParse(Value, out var ConvertValue))
            return -1;

        return ConvertValue;
    }
    protected virtual int? GetIntNull([CallerMemberName] string PropertyName = null)
    {
        if (!TryGetValue(PropertyName, out var Value) || !int.TryParse(Value, out var ConvertValue))
            return null;

        return ConvertValue;
    }
    protected virtual List<TValue> GetList<TValue>([CallerMemberName] string PropertyName = null)
    {
        if (!TryGetValue(PropertyName, out var Value))
            return null;

        var TryGetList = JsonSerializer.Deserialize<List<TValue>>(Value);
        return TryGetList;
    }
    protected virtual DateTime GetTokenExpiredDatetime()
    {
        var GetExp = GetString("exp");
        if (long.TryParse(GetExp, out var Time))
            return DateTimeOffset.FromUnixTimeSeconds(Time).LocalDateTime;

        return DateTime.MinValue;
    }
    #endregion

    #region Claims Control
    public IUserInfo SetClaims(IEnumerable<Claim> Claims)
    {
        this.Claims = Claims.ToList() ?? new();
        return this;
    }
    public IUserInfo AddClaim(string Type, object Value, ClaimsValueType ValueType)
    {
        var GetValueType = ValueType switch
        {
            ClaimsValueType.String => ClaimValueTypes.String,
            ClaimsValueType.Integer => ClaimValueTypes.Integer,
            ClaimsValueType.Boolean => ClaimValueTypes.Boolean,
            _ => ClaimValueTypes.String
        };
        Claims.Add(new Claim(Type, Value?.ToString() ?? "", GetValueType));
        return this;
    }
    public IUserInfo AddClaims(IEnumerable<Claim> Claims)
    {
        this.Claims.AddRange(Claims);
        return this;
    }
    public virtual Dictionary<string, object> GetClaimsInfo()
    {
        var Resultt = new Dictionary<string, object> { };
        foreach (var Item in Claims)
        {
            var GetType = Item.ValueType.ToLower();
            var GetValue = Item.Value;
            if (GetType == ClaimValueTypes.Boolean && bool.TryParse(GetValue, out var OutBoolean))
                Resultt.TryAdd(Item.Type, OutBoolean);
            else if (GetType == ClaimValueTypes.Integer && int.TryParse(GetValue, out var OutInt))
                Resultt.TryAdd(Item.Type, OutInt);
            else
                Resultt.TryAdd(Item.Type, GetValue);
        }
        return Resultt;
    }
    public virtual bool TryGetValue(string PropertyName, out string OutValue)
    {
        OutValue = null;
        var GetClaim = Claims.FirstOrDefault(Item => Item.Type == PropertyName);
        if (GetClaim is not null)
        {
            OutValue = GetClaim.Value;
            return true;
        }
        return false;
    }
    #endregion
}
public enum ClaimsValueType
{
    String,
    Integer,
    Boolean
}