use alloy_sol_types::sol;

// Some solidity function definition from the contracts v2
sol! {
    /// Content registry stuff
    function isExistingContent(uint256 _contentId) public view returns (bool);
    function getContentTypes(uint256 _contentId) public view returns (uint256);
    function isAuthorized(uint256 _contentId, address _caller) public view returns (bool);
}
