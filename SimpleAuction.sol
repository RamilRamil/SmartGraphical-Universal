// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleAuction {
    address public owner;
    mapping(address => uint) public bids;
    address public highestBidder;
    uint public highestBid;
    bool public ended;

    event BidPlaced(address bidder, uint amount);
    event AuctionEnded(address winner, uint amount);

    constructor() {
        owner = msg.sender;
        highestBid = 0;
        highestBidder = address(0);
        ended = false;
    }

    function bid() public payable {
        require(!ended, "Auction has ended.");
        require(msg.value > highestBid, "There must be a higher bid.");

        if (highestBidder != address(0)) {
            bids[highestBidder] += highestBid; // Refund the previous highest bidder
        }
        bids[msg.sender] += msg.value;
        highestBidder = msg.sender;
        highestBid = msg.value;
        emit BidPlaced(msg.sender, msg.value);
    }

    function withdraw() public {
        require(!ended, "Auction has ended.");
        uint amount = bids[msg.sender];
        bids[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    function endAuction() public onlyOwner {
        require(!ended, "Auction already ended.");
        ended = true;
        emit AuctionEnded(highestBidder, highestBid);
        payable(highestBidder).transfer(highestBid);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can call this function.");
        _;
    }
}