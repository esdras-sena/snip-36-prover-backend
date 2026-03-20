#[starknet::interface]
trait ICounter<TContractState> {
    fn increment(ref self: TContractState, amount: felt252);
    fn get_counter(self: @TContractState) -> felt252;
}

#[starknet::contract]
mod Counter {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        counter: felt252,
    }

    #[abi(embed_v0)]
    impl CounterImpl of super::ICounter<ContractState> {
        fn increment(ref self: ContractState, amount: felt252) {
            self.counter.write(self.counter.read() + amount);
        }

        fn get_counter(self: @ContractState) -> felt252 {
            self.counter.read()
        }
    }
}

#[starknet::interface]
trait IMessenger<TContractState> {
    fn send_message(ref self: TContractState, to_address: felt252, payload: Span<felt252>);
}

#[starknet::contract]
mod Messenger {
    use starknet::syscalls::send_message_to_l1_syscall;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl MessengerImpl of super::IMessenger<ContractState> {
        fn send_message(ref self: ContractState, to_address: felt252, payload: Span<felt252>) {
            send_message_to_l1_syscall(to_address, payload).unwrap();
        }
    }
}
