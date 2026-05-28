defmodule SamlySpHandlerTest do
  use ExUnit.Case
  alias Samly.{Assertion, IdpData, SPHandler}

  defp build_assertion(idp_id, nameid) do
    %Assertion{
      idp_id: idp_id,
      subject: %Samly.Subject{name: nameid},
      attributes: %{},
      authn: %{}
    }
  end

  describe "maybe_call_on_logout/3" do
    test "calls callback with idp_id and assertion" do
      test_pid = self()
      callback = fn idp_id, assertion -> send(test_pid, {:logout, idp_id, assertion}) end
      idp = %IdpData{on_logout: callback}
      assertion = build_assertion("okta-prod", "user@example.com")

      SPHandler.maybe_call_on_logout(idp, "okta-prod", assertion)

      assert_received {:logout, "okta-prod", ^assertion}
    end

    test "no-ops when on_logout is nil" do
      idp = %IdpData{on_logout: nil}
      assertion = build_assertion("okta", "user@test.com")
      assert :ok == SPHandler.maybe_call_on_logout(idp, "okta", assertion)
    end

    test "catches exceptions without raising" do
      callback = fn _, _ -> raise "boom" end
      idp = %IdpData{on_logout: callback}
      assertion = build_assertion("okta", "user@test.com")

      assert :ok == SPHandler.maybe_call_on_logout(idp, "okta", assertion)
    end

    test "catches throws without raising" do
      callback = fn _, _ -> throw(:oops) end
      idp = %IdpData{on_logout: callback}
      assertion = build_assertion("okta", "user@test.com")

      assert :ok == SPHandler.maybe_call_on_logout(idp, "okta", assertion)
    end

    test "catches exits without raising" do
      callback = fn _, _ -> exit(:shutdown) end
      idp = %IdpData{on_logout: callback}
      assertion = build_assertion("okta", "user@test.com")

      assert :ok == SPHandler.maybe_call_on_logout(idp, "okta", assertion)
    end
  end
end
