#ifndef __CVMX_CONFIG_H__
#define __CVMX_CONFIG_H__

/**
 * @file config/cvmx-config.h
 *
 * Auto generated config file for the Cavium Octeon Executive.
 * This file should not be edited, as it will be overwritten by cvmx-config.
 */

/************************* Config Specific Defines ************************/
#define CVMX_LLM_NUM_PORTS 1
#define CVMX_NULL_POINTER_PROTECT 1
#define CVMX_ENABLE_DEBUG_PRINTS 1
#define CVMX_PKO_QUEUES_PER_PORT_INTERFACE0 1               /**< PKO queues per port for interface 0 (ports 0-15) */
#define CVMX_PKO_QUEUES_PER_PORT_INTERFACE1 1               /**< PKO queues per port for interface 1 (ports 16-31) */
#define CVMX_PKO_QUEUES_PER_PORT_INTERFACE2 CVMX_HELPER_PKO_QUEUES_PER_PORT_INTERFACE2 /**< PKO queues per port for interface 2 */
#define CVMX_PKO_QUEUES_PER_PORT_INTERFACE3 CVMX_HELPER_PKO_QUEUES_PER_PORT_INTERFACE3 /**< PKO queues per port for interface 3 */
#define CVMX_PKO_QUEUES_PER_PORT_INTERFACE4 CVMX_HELPER_PKO_QUEUES_PER_PORT_INTERFACE4 /**< PKO queues per port for interface 4 */
#define CVMX_PKO_QUEUES_PER_PORT_INTERFACE5 CVMX_HELPER_PKO_QUEUES_PER_PORT_INTERFACE5 /**< PKO queues per port for interface 5 */
#define CVMX_QOS_PER_PORT_INTERFACE0 CVMX_HELPER_QOS_PER_PORT_INTERFACE0 /**< Prioritize packets on interface 0 */
#define CVMX_QOS_PER_PORT_INTERFACE1 CVMX_HELPER_QOS_PER_PORT_INTERFACE1 /**< Prioritize packets on interface 1 */
#define CVMX_QOS_PER_PORT_INTERFACE2 CVMX_HELPER_QOS_PER_PORT_INTERFACE2 /**< Prioritize packets on interface 2 */
#define CVMX_QOS_PER_PORT_INTERFACE3 CVMX_HELPER_QOS_PER_PORT_INTERFACE3 /**< Prioritize packets on interface 3 */
#define CVMX_QOS_PER_PORT_INTERFACE4 CVMX_HELPER_QOS_PER_PORT_INTERFACE4 /**< Prioritize packets on interface 4 */
#define CVMX_QOS_PER_PORT_INTERFACE5 CVMX_HELPER_QOS_PER_PORT_INTERFACE5 /**< Prioritize packets on interface 5 */
#define CVMX_PKO_MAX_PORTS_INTERFACE0 CVMX_HELPER_PKO_MAX_PORTS_INTERFACE0 /**< Limit on the number of PKO ports enabled for interface 0 */
#define CVMX_PKO_MAX_PORTS_INTERFACE1 CVMX_HELPER_PKO_MAX_PORTS_INTERFACE1 /**< Limit on the number of PKO ports enabled for interface 1 */
#define CVMX_PKO_QUEUES_PER_PORT_PCI 1                      /**< PKO queues per port for PCI (ports 32-35) */
#define CVMX_PKO_QUEUES_PER_PORT_LOOP 1                     /**< PKO queues per port for Loop devices (ports 36-39) */
#define CVMX_PKO_QUEUES_PER_PORT_SRIO0 2                    /**< PKO queues per port for SRIO0 devices (ports 40-41) */
#define CVMX_PKO_QUEUES_PER_PORT_SRIO1 2                    /**< PKO queues per port for SRIO1 devices (ports 42-43) */
#define CVMX_IPD_DRAM_MODE CVMX_HELPER_IPD_DRAM_MODE        /**< set the IPD cache mode to CVMX_IPD_OPC_MODE_STT */

/************************* FPA allocation *********************************/
/* Pool sizes in bytes, must be multiple of a cache line */
#define CVMX_FPA_POOL_0_SIZE (16 * CVMX_CACHE_LINE_SIZE)
#define CVMX_FPA_POOL_1_SIZE (1 * CVMX_CACHE_LINE_SIZE)
#define CVMX_FPA_POOL_2_SIZE (8 * CVMX_CACHE_LINE_SIZE)
#define CVMX_FPA_POOL_3_SIZE (1 * CVMX_CACHE_LINE_SIZE)
#define CVMX_FPA_POOL_4_SIZE (32 * CVMX_CACHE_LINE_SIZE)
#define CVMX_FPA_POOL_5_SIZE (0 * CVMX_CACHE_LINE_SIZE)
#define CVMX_FPA_POOL_6_SIZE (0 * CVMX_CACHE_LINE_SIZE)
#define CVMX_FPA_POOL_7_SIZE (0 * CVMX_CACHE_LINE_SIZE)

/* Pools in use */
#define CVMX_FPA_PACKET_POOL                (0)             /**< Packet buffers */
#define CVMX_FPA_PACKET_POOL_SIZE           CVMX_FPA_POOL_0_SIZE
#define CVMX_FPA_WQE_POOL                   (1)             /**< Work queue entrys */
#define CVMX_FPA_WQE_POOL_SIZE              CVMX_FPA_POOL_1_SIZE
#define CVMX_FPA_OUTPUT_BUFFER_POOL         (2)             /**< PKO queue command buffers */
#define CVMX_FPA_OUTPUT_BUFFER_POOL_SIZE    CVMX_FPA_POOL_2_SIZE
#define CVM_FPA_128B_POOL                   (3)             /**< 128-byte FPA pool */
#define CVM_FPA_128B_POOL_SIZE              CVMX_FPA_POOL_3_SIZE
#define CVM_FPA_DRV_POOL                    (4)             /**< 4096-byte Core drv FPA pool */
#define CVM_FPA_DRV_POOL_SIZE               CVMX_FPA_POOL_4_SIZE

/*************************  FAU allocation ********************************/
/* The fetch and add registers are allocated here.  They are arranged
    in order of descending size so that all alignment constraints are
    automatically met.
    The enums are linked so that the following enum continues allocating
    where the previous one left off, so the numbering within each
    enum always starts with zero.  The macros take care of the address
    increment size, so the values entered always increase by 1.
    FAU registers are accessed with byte addresses. */

#define CVMX_FAU_REG_64_ADDR(x) ((x <<3) + CVMX_FAU_REG_64_START)
typedef enum
{
    CVMX_FAU_REG_64_START          = 0, 
    CVMX_FAU_REG_64_END            = CVMX_FAU_REG_64_ADDR(0),
} cvmx_fau_reg_64_t;

#define CVMX_FAU_REG_32_ADDR(x) ((x <<2) + CVMX_FAU_REG_32_START)
typedef enum
{
    CVMX_FAU_REG_32_START          = CVMX_FAU_REG_64_END,
    CVMX_FAU_REG_POOL_0_USE_COUNT  = CVMX_FAU_REG_32_ADDR(0), /**< pool 0 use count */
    CVMX_FAU_REG_POOL_1_USE_COUNT  = CVMX_FAU_REG_32_ADDR(1), /**< pool 1 use count */
    CVMX_FAU_REG_POOL_2_USE_COUNT  = CVMX_FAU_REG_32_ADDR(2), /**< pool 2 use count */
    CVMX_FAU_REG_POOL_3_USE_COUNT  = CVMX_FAU_REG_32_ADDR(3), /**< pool 3 use count */
    CVMX_FAU_REG_POOL_4_USE_COUNT  = CVMX_FAU_REG_32_ADDR(4), /**< pool 4 use count */
    CVMX_FAU_REG_POOL_5_USE_COUNT  = CVMX_FAU_REG_32_ADDR(5), /**< pool 5 use count */
    CVMX_FAU_REG_POOL_6_USE_COUNT  = CVMX_FAU_REG_32_ADDR(6), /**< pool 6 use count */
    CVMX_FAU_REG_POOL_7_USE_COUNT  = CVMX_FAU_REG_32_ADDR(7), /**< pool 7 use count */
    CVMX_FAU_REG_32_END            = CVMX_FAU_REG_32_ADDR(8),
} cvmx_fau_reg_32_t;

#define CVMX_FAU_REG_16_ADDR(x) ((x <<1) + CVMX_FAU_REG_16_START)
typedef enum
{
    CVMX_FAU_REG_16_START          = CVMX_FAU_REG_32_END,
    CVMX_FAU_REG_16_END            = CVMX_FAU_REG_16_ADDR(0),
} cvmx_fau_reg_16_t;

#define CVMX_FAU_REG_8_ADDR(x) ((x) + CVMX_FAU_REG_8_START)
typedef enum {
    CVMX_FAU_REG_8_START           = CVMX_FAU_REG_16_END,
    CVMX_FAU_REG_8_END             = CVMX_FAU_REG_8_ADDR(0),
} cvmx_fau_reg_8_t;

/* The name CVMX_FAU_REG_AVAIL_BASE is provided to indicate the first available
   FAU address that is not allocated in cvmx-config.h. This is 64 bit aligned. */
#define CVMX_FAU_REG_AVAIL_BASE ((CVMX_FAU_REG_8_END + 0x7) & (~0x7ULL))
#define CVMX_FAU_REG_END (2048)

/********************** scratch memory allocation *************************/
/* Scratchpad memory allocation.  Note that these are byte memory addresses.
    Some uses of scratchpad (IOBDMA for example) require the use of 8-byte
    aligned addresses, so proper alignment needs to be taken into account. */

#define CVMX_SCR_WQE_BUF_PTR           (0)                  /**< Scratch pad location for 256-byte buffer pointer */
#define CVMX_SCR_PACKET_BUF_PTR        (8)                  /**< Scratch pad location for packet buffer pointer */
#define CVM_SCR_128B_BUF_PTR           (16)                 /**< Scratch pad location for 128-byte buffer pointer */
#define CVM_SCR_ADDITIONAL_128B_BUF_PTR (24)                /**< Another scratch pad location for 128-byte buffer pointer */
#define CVM_SCR_DRV_BUF_PTR            (32)                 /**< Scratch pad location for 4096-byte core drv buffer pointer */
#define CVM_SCR_GATHER_BUF_PTR         (40)                 /**< Scratch pad location for gather buffer pointer */
#define CVM_SCR_MBUFF_INFO_PTR         (48)                 /**< Scratch pad location for  mbuff sizes */
#define CVMX_SCR_SCRATCH               (56)                 /**< Generic scratch iobdma area */
#define CVMX_SCR_REG_AVAIL_BASE        (64)                 /**< First location available after cvmx-config.h allocated region. */

#endif /* __CVMX_CONFIG_H__ */

