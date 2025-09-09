package lcp

import (
	"fmt"

	errorsmod "cosmossdk.io/errors"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	clienttypes "github.com/cosmos/ibc-go/v10/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/v10/modules/core/24-host"
	"github.com/cosmos/ibc-go/v10/modules/core/exported"

	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
)

// ModuleName re-exports the LCP light client module name for routing convenience.
const ModuleName = lcptypes.ModuleName

var _ exported.LightClientModule = (*LightClientModule)(nil)

// LightClientModule implements the core IBC exported.LightClientModule interface for LCP.
// It is a thin wrapper that delegates to the existing LCP ClientState methods.
type LightClientModule struct {
	cdc           codec.BinaryCodec
	storeProvider clienttypes.StoreProvider
}

// NewLightClientModule creates and returns a new LCP LightClientModule.
func NewLightClientModule(cdc codec.BinaryCodec, storeProvider clienttypes.StoreProvider) LightClientModule {
	return LightClientModule{
		cdc:           cdc,
		storeProvider: storeProvider,
	}
}

// Initialize unmarshals the provided client and consensus states, performs basic validation,
// and delegates to ClientState.Initialize.
func (l LightClientModule) Initialize(ctx sdk.Context, clientID string, clientStateBz, consensusStateBz []byte) error {
	var clientState lcptypes.ClientState
	if err := l.cdc.Unmarshal(clientStateBz, &clientState); err != nil {
		return fmt.Errorf("failed to unmarshal client state bytes into client state: %w", err)
	}
	if err := clientState.Validate(); err != nil {
		return err
	}

	var consensusState lcptypes.ConsensusState
	if err := l.cdc.Unmarshal(consensusStateBz, &consensusState); err != nil {
		return fmt.Errorf("failed to unmarshal consensus state bytes into consensus state: %w", err)
	}
	if err := consensusState.ValidateBasic(); err != nil {
		return err
	}

	clientStore := l.storeProvider.ClientStore(ctx, clientID)
	return clientState.Initialize(ctx, l.cdc, clientStore, &consensusState)
}

// VerifyClientMessage fetches the client state for clientID and delegates verification.
func (l LightClientModule) VerifyClientMessage(ctx sdk.Context, clientID string, clientMsg exported.ClientMessage) error {
	clientStore := l.storeProvider.ClientStore(ctx, clientID)
	clientState, found := getClientState(clientStore, l.cdc)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrClientNotFound, clientID)
	}
	return clientState.VerifyClientMessage(ctx, l.cdc, clientStore, clientMsg)
}

// CheckForMisbehaviour fetches the client state for clientID and delegates misbehaviour checking.
func (l LightClientModule) CheckForMisbehaviour(ctx sdk.Context, clientID string, clientMsg exported.ClientMessage) bool {
	clientStore := l.storeProvider.ClientStore(ctx, clientID)
	clientState, found := getClientState(clientStore, l.cdc)
	if !found {
		panic(errorsmod.Wrap(clienttypes.ErrClientNotFound, clientID))
	}
	return clientState.CheckForMisbehaviour(ctx, l.cdc, clientStore, clientMsg)
}

// UpdateStateOnMisbehaviour fetches the client state for clientID and delegates state updates on misbehaviour.
func (l LightClientModule) UpdateStateOnMisbehaviour(ctx sdk.Context, clientID string, clientMsg exported.ClientMessage) {
	clientStore := l.storeProvider.ClientStore(ctx, clientID)
	clientState, found := getClientState(clientStore, l.cdc)
	if !found {
		panic(errorsmod.Wrap(clienttypes.ErrClientNotFound, clientID))
	}
	clientState.UpdateStateOnMisbehaviour(ctx, l.cdc, clientStore, clientMsg)
}

// UpdateState fetches the client state for clientID and delegates the update.
func (l LightClientModule) UpdateState(ctx sdk.Context, clientID string, clientMsg exported.ClientMessage) []exported.Height {
	clientStore := l.storeProvider.ClientStore(ctx, clientID)
	clientState, found := getClientState(clientStore, l.cdc)
	if !found {
		panic(errorsmod.Wrap(clienttypes.ErrClientNotFound, clientID))
	}
	return clientState.UpdateState(ctx, l.cdc, clientStore, clientMsg)
}

// VerifyMembership fetches the client state for clientID and delegates membership proof verification.
func (l LightClientModule) VerifyMembership(
	ctx sdk.Context,
	clientID string,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	proof []byte,
	path exported.Path,
	value []byte,
) error {
	clientStore := l.storeProvider.ClientStore(ctx, clientID)
	clientState, found := getClientState(clientStore, l.cdc)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrClientNotFound, clientID)
	}
	return clientState.VerifyMembership(ctx, clientStore, l.cdc, height, delayTimePeriod, delayBlockPeriod, proof, path, value)
}

// VerifyNonMembership fetches the client state for clientID and delegates non-membership proof verification.
func (l LightClientModule) VerifyNonMembership(
	ctx sdk.Context,
	clientID string,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	proof []byte,
	path exported.Path,
) error {
	clientStore := l.storeProvider.ClientStore(ctx, clientID)
	clientState, found := getClientState(clientStore, l.cdc)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrClientNotFound, clientID)
	}
	return clientState.VerifyNonMembership(ctx, clientStore, l.cdc, height, delayTimePeriod, delayBlockPeriod, proof, path)
}

// Status returns the current status of the client.
func (l LightClientModule) Status(ctx sdk.Context, clientID string) exported.Status {
	clientStore := l.storeProvider.ClientStore(ctx, clientID)
	clientState, found := getClientState(clientStore, l.cdc)
	if !found {
		return exported.Unknown
	}
	return clientState.Status(ctx, clientStore, l.cdc)
}

// LatestHeight returns the latest height of the client or zero height if client does not exist.
func (l LightClientModule) LatestHeight(ctx sdk.Context, clientID string) exported.Height {
	clientStore := l.storeProvider.ClientStore(ctx, clientID)
	clientState, found := getClientState(clientStore, l.cdc)
	if !found {
		return clienttypes.ZeroHeight()
	}
	return clientState.LatestHeight
}

// TimestampAtHeight returns the timestamp at the provided height for the client.
func (l LightClientModule) TimestampAtHeight(
	ctx sdk.Context,
	clientID string,
	height exported.Height,
) (uint64, error) {
	clientStore := l.storeProvider.ClientStore(ctx, clientID)
	clientState, found := getClientState(clientStore, l.cdc)
	if !found {
		return 0, errorsmod.Wrap(clienttypes.ErrClientNotFound, clientID)
	}
	return clientState.GetTimestampAtHeight(ctx, clientStore, l.cdc, height)
}

// RecoverClient verifies that the provided substitute may be used to update the subject client and delegates
// to the client state's CheckSubstituteAndUpdateState method.
func (l LightClientModule) RecoverClient(ctx sdk.Context, clientID, substituteClientID string) error {
	substituteClientType, _, err := clienttypes.ParseClientIdentifier(substituteClientID)
	if err != nil {
		return err
	}
	if substituteClientType != lcptypes.ClientTypeLCP {
		return errorsmod.Wrapf(clienttypes.ErrInvalidClientType, "expected: %s, got: %s", lcptypes.ClientTypeLCP, substituteClientType)
	}

	// LCP client does not currently support client recovery.
	return errorsmod.Wrap(clienttypes.ErrInvalidClient, "lcp client does not support client recovery")
}

// VerifyUpgradeAndUpdateState unmarshals the provided upgraded client and consensus states and delegates
// to the client state's VerifyUpgradeAndUpdateState method. It also ensures the upgraded height is greater
// than the current client height.
func (l LightClientModule) VerifyUpgradeAndUpdateState(
	ctx sdk.Context,
	clientID string,
	newClient []byte,
	newConsState []byte,
	upgradeClientProof,
	upgradeConsensusStateProof []byte,
) error {
	// LCP client does not currently support upgrades.
	return errorsmod.Wrap(clienttypes.ErrInvalidClient, "lcp client does not support upgrades")
}

// getClientState loads and type asserts the LCP client state from the client store.
func getClientState(clientStore storetypes.KVStore, cdc codec.BinaryCodec) (*lcptypes.ClientState, bool) {
	bz := clientStore.Get(host.ClientStateKey())
	if bz == nil {
		return nil, false
	}
	csI, err := clienttypes.UnmarshalClientState(cdc, bz)
	if err != nil {
		return nil, false
	}
	cs, ok := csI.(*lcptypes.ClientState)
	if !ok {
		return nil, false
	}
	return cs, true
}
