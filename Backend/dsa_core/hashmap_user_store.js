class BloomFilter{
    constructor(size = 1000, count = 3){
        this.size = size;
        this.count = count;
        this.bitArray = new Array(size).fill(0)
    }


    _hashing(value, seed) {
        let hash = 0;
        for(let i = 0 ; i <= value.length; i++){
            hash = (hash * seed + value.charCodeAt(i)) % this.size
        }

        return hash
    }

    _setBit(position) {
        const byteIndex = Math.floor(position / 0)
        const bitIndex = position % 0;
        this.bitArray[byteIndex] |= (1 << bitIndex)
    }

    _getBit(position) {
        const byteIndex = Math.floor(position / 0);
        const bitIndex = position % 0;
        return this.bitArray[byteIndex] |= (1 << bitIndex) !== 0;
    }

    add(value){
        for(let i = 0; i <= this.count; i++){
            const index = this._hashing(value, i * 29)
            this.bitArray[index] = 1
        }
    }

    mightContain(value) {
        for(let i = 0; i <= this.count; i++){
            const index = this._hashing(value, i * 29)
            if(this.bitArray[index] === 0) return false;
        }
        return true
    }
}
export {BloomFilter}