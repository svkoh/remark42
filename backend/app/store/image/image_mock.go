// Code generated by mockery v1.1.2. DO NOT EDIT.

package image

import (
	context "context"
	time "time"

	mock "github.com/stretchr/testify/mock"
)

// MockStore is an autogenerated mock type for the Store type
type MockStore struct {
	mock.Mock
}

// Cleanup provides a mock function with given fields: ctx, ttl
func (_m *MockStore) Cleanup(ctx context.Context, ttl time.Duration) error {
	ret := _m.Called(ctx, ttl)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, time.Duration) error); ok {
		r0 = rf(ctx, ttl)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Commit provides a mock function with given fields: id
func (_m *MockStore) Commit(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Info provides a mock function with given fields:
func (_m *MockStore) Info() (StoreInfo, error) {
	ret := _m.Called()

	var r0 StoreInfo
	if rf, ok := ret.Get(0).(func() StoreInfo); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(StoreInfo)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Load provides a mock function with given fields: id
func (_m *MockStore) Load(id string) ([]byte, error) {
	ret := _m.Called(id)

	var r0 []byte
	if rf, ok := ret.Get(0).(func(string) []byte); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Save provides a mock function with given fields: id, img
func (_m *MockStore) Save(id string, img []byte) error {
	ret := _m.Called(id, img)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, []byte) error); ok {
		r0 = rf(id, img)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
