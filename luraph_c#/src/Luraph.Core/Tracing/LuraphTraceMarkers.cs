namespace Luraph.Core.Tracing;

public static class LuraphTraceMarkers
{
    public const string Call = "@@LPH_CALL_V2@@";
    public const string Vm = "@@LPH_VM@@";
    public const string Activation = "@@LPH_ACTIVATION@@";
    public const string Prototype = "@@LPH_PROTO_V1@@";
    public const string PrototypeObject = "@@LPH_PROTO_OBJECT_V1@@";
    public const string Instruction = "@@LPH_INSN_V1@@";
    public const string LaneTop = "@@LPH_LANE_TOP_V1@@";
    public const string LaneTable = "@@LPH_LANE_TABLE_V1@@";
    public const string ActivationPrototype = "@@LPH_ACT_PROTO_V1@@";
    public const string ActivationArgumentTable = "@@LPH_ACT_ARG_TABLE_V1@@";
    public const string CaptureDomain = "@@LPH_CAPTURE_DOMAIN_V1@@";
    public const string Step = "@@LPH_STEP_V1@@";
    public const string Return = "@@LPH_RETURN_V1@@";

    public const string Prefix = "@@LPH_";
}
