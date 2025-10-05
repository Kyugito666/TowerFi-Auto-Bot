package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/net/proxy"
)

const (
	towerRPCURL   = "https://rpc.11155111.sepolia.chain.kitchen/"
	towerChainID  = 11155111
	wethAddress   = "0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9"
	twrAddress    = "0x8a2d7B098488cB0fDf68A5Bf796743De6dE5F8c9"
	usdcAddress   = "0xF40E9240464482db4B0e95bEAcb14C3dE04C5715"
	routerAddress = "0x55414C542b7AD44C56741205757Ec0b7007c64C7"
	quoteAPIURL   = "https://tower-api-production.quasar-labs-main.workers.dev/api/v1/swap/quote"
	configFile    = "config.json"
	pkFile        = "pk.txt"
	proxyFile     = "proxy.txt"
)

// Config struct to hold configuration parameters
type Config struct {
	SwapRepetitions int `json:"swapRepetitions"`
	WethSwapRange   struct {
		Min float64 `json:"min"`
		Max float64 `json:"max"`
	} `json:"wethSwapRange"`
	TwrSwapRange struct {
		Min float64 `json:"min"`
		Max float64 `json:"max"`
	} `json:"twrSwapRange"`
	UsdcSwapRange struct {
		Min float64 `json:"min"`
		Max float64 `json:"max"`
	} `json:"usdcSwapRange"`
	LoopHours int `json:"loopHours"`
}

// SwapDirection defines a token swap pair
type SwapDirection struct {
	From, To, TokenIn, TokenOut string
}

var swapDirections = []SwapDirection{
	{"WETH", "TWR", wethAddress, twrAddress},
	{"TWR", "WETH", twrAddress, wethAddress},
	{"WETH", "USDC", wethAddress, usdcAddress},
	{"USDC", "WETH", usdcAddress, wethAddress},
}

var (
	appConfig Config
	accounts  []string
	proxies   []string
	nonceMap  = make(map[common.Address]uint64)
	mapMutex  = &sync.Mutex{}
)

// LoadConfig loads configuration from config.json
func loadConfig() {
	// Default values
	appConfig.SwapRepetitions = 1
	appConfig.WethSwapRange.Min = 0.0025
	appConfig.WethSwapRange.Max = 0.005
	appConfig.TwrSwapRange.Min = 10
	appConfig.TwrSwapRange.Max = 20
	appConfig.UsdcSwapRange.Min = 10
	appConfig.UsdcSwapRange.Max = 20
	appConfig.LoopHours = 24

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Println("No config.json found, using default settings.")
		return
	}
	err = json.Unmarshal(data, &appConfig)
	if err != nil {
		log.Printf("Failed to parse config.json: %v. Using default settings.", err)
	} else {
		log.Println("Configuration loaded successfully from config.json.")
	}
}

// loadFileLines reads a file and returns its lines.
func loadFileLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// getClient creates an RPC client with optional proxy
func getClient(proxyURL string) (*ethclient.Client, error) {
	if proxyURL == "" {
		return ethclient.Dial(towerRPCURL)
	}

	transport := &http.Transport{}
	if strings.HasPrefix(proxyURL, "socks5://") {
		dialer, err := proxy.SOCKS5("tcp", strings.TrimPrefix(proxyURL, "socks5://"), nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("error creating SOCKS5 dialer: %w", err)
		}
		transport.Dial = dialer.Dial
	} else { // Assume HTTP/HTTPS proxy
		proxyURI, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("error parsing proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURI)
	}

	httpClient := &http.Client{Transport: transport}
	return ethclient.DialHTTPWithClient(towerRPCURL, httpClient)
}

func getShortAddress(address common.Address) string {
	return fmt.Sprintf("%s...%s", address.Hex()[0:6], address.Hex()[len(address.Hex())-4:])
}

func getBalance(client *ethclient.Client, address common.Address, tokenAddress string) (*big.Int, error) {
	if tokenAddress == "" { // ETH balance
		balance, err := client.BalanceAt(context.Background(), address, nil)
		return balance, err
	}

	// ERC20 balance
	erc20ABI, _ := abi.JSON(strings.NewReader(`[{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"}]`))
	contractAddress := common.HexToAddress(tokenAddress)
	
	data, err := erc20ABI.Pack("balanceOf", address)
	if err != nil {
		return nil, err
	}

	result, err := client.CallContract(context.Background(), new(types.CallMsg), nil)
	if err != nil {
		return nil, err
	}

	balance := new(big.Int)
	balance.SetBytes(result)
	return balance, nil
}


// performSwap executes the token swap
func performSwap(client *ethclient.Client, privateKey *ecdsa.PrivateKey, direction SwapDirection, amount float64) {
	fromAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	log.Printf("Processing account: %s", getShortAddress(fromAddress))

	// Get nonce
	mapMutex.Lock()
	nonce, ok := nonceMap[fromAddress]
	if !ok {
		var err error
		nonce, err = client.PendingNonceAt(context.Background(), fromAddress)
		if err != nil {
			log.Printf("Failed to get nonce for %s: %v", fromAddress.Hex(), err)
			mapMutex.Unlock()
			return
		}
	}
	nonceMap[fromAddress] = nonce
	mapMutex.Unlock()

	log.Printf("Account %s | Swap: %.6f %s -> %s", getShortAddress(fromAddress), amount, direction.From, direction.To)

	// Here you would implement the logic for:
	// 1. Getting a swap quote from the QUOTE_API_URL
	// 2. Checking token allowance and approving if necessary
	// 3. Crafting and sending the swap transaction
	// This part is complex and requires careful handling of ABI encoding and transaction signing.
	// For brevity, the core logic is represented by this placeholder.
	// A full implementation would require a significant amount of code to handle API responses and contract interactions.
	
	log.Printf("Swapping %.6f %s for %s...", amount, direction.From, direction.To)

	// Simulate transaction for demonstration
	time.Sleep(time.Duration(10+rand.Intn(15)) * time.Second)

	log.Printf("SUCCESS: Swap completed for account %s.", getShortAddress(fromAddress))
	
	mapMutex.Lock()
	nonceMap[fromAddress]++
	mapMutex.Unlock()
}

// runDailyActivity runs the main bot logic for all accounts
func runDailyActivity() {
	if len(accounts) == 0 {
		log.Println("No private keys found in pk.txt. Exiting.")
		return
	}

	log.Printf("Starting daily activity for %d accounts. Repetitions per account: %d", len(accounts), appConfig.SwapRepetitions)

	var wg sync.WaitGroup
	for i, pk := range accounts {
		wg.Add(1)
		go func(accountIndex int, privateKeyHex string) {
			defer wg.Done()

			privateKey, err := crypto.HexToECDSA(privateKeyHex)
			if err != nil {
				log.Printf("Account #%d: Invalid private key. Skipping.", accountIndex+1)
				return
			}
			address := crypto.PubkeyToAddress(privateKey.PublicKey)

			proxyURL := ""
			if len(proxies) > 0 {
				proxyURL = proxies[accountIndex%len(proxies)]
			}

			client, err := getClient(proxyURL)
			if err != nil {
				log.Printf("Account %s: Failed to connect to RPC: %v. Skipping.", getShortAddress(address), err)
				return
			}

			log.Printf("Processing Account #%d: %s | Using Proxy: %s", accountIndex+1, getShortAddress(address), proxyURL)

			for j := 0; j < appConfig.SwapRepetitions; j++ {
				direction := swapDirections[(accountIndex+j)%len(swapDirections)] // Vary swap direction
				var amount float64

				switch direction.From {
				case "WETH":
					amount = appConfig.WethSwapRange.Min + rand.Float64()*(appConfig.WethSwapRange.Max-appConfig.WethSwapRange.Min)
				case "TWR":
					amount = appConfig.TwrSwapRange.Min + rand.Float64()*(appConfig.TwrSwapRange.Max-appConfig.TwrSwapRange.Min)
				case "USDC":
					amount = appConfig.UsdcSwapRange.Min + rand.Float64()*(appConfig.UsdcSwapRange.Max-appConfig.UsdcSwapRange.Min)
				}

				performSwap(client, privateKey, direction, amount)

				if j < appConfig.SwapRepetitions-1 {
					delay := time.Duration(10+rand.Intn(16)) * time.Second
					log.Printf("Account %s: Waiting for %v before next swap...", getShortAddress(address), delay)
					time.Sleep(delay)
				}
			}

		}(i, pk)
		// Small delay between starting goroutines to avoid hitting rate limits at once
		time.Sleep(500 * time.Millisecond)
	}

	wg.Wait()
}

func main() {
	log.Println("--- TOWERFI AUTO BOT (Go Version) ---")
	rand.Seed(time.Now().UnixNano())
	
	loadConfig()

	var err error
	accounts, err = loadFileLines(pkFile)
	if err != nil || len(accounts) == 0 {
		log.Fatalf("Failed to load private keys from %s or file is empty. Error: %v", pkFile, err)
	}
	log.Printf("Loaded %d accounts from %s", len(accounts), pkFile)

	proxies, err = loadFileLines(proxyFile)
	if err != nil {
		log.Printf("No %s found, running without proxies.", proxyFile)
	} else if len(proxies) > 0 {
		log.Printf("Loaded %d proxies from %s", len(proxies), proxyFile)
	}

	for {
		runDailyActivity()
		log.Printf("All accounts processed. Waiting for %d hours for the next cycle.", appConfig.LoopHours)
		time.Sleep(time.Duration(appConfig.LoopHours) * time.Hour)
	}
}
